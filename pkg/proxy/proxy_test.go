package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"evan-proxy/pkg/acl"
	"evan-proxy/pkg/config"
	edns "evan-proxy/pkg/dns"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/ratelimit"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

func setupProxy(t *testing.T) *Handler {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.db")
	users, err := userdb.Open(dbPath, logging.New(logging.NewConsoleBackend(io.Discard, "human")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })

	cfg := &config.Config{
		AuthRetryTimeout:   5 * time.Second,
		ConnectDialTimeout: 5 * time.Second,
		IdleTimeout:        30 * time.Second,
		HTTPTimeout:        10 * time.Second,
		DNSProtocol:        "plain",
		UserPortMin:        18081,
		UserPortMax:        18090,
	}

	port, err := users.Add("alice", "secret", cfg.UserPortMin, cfg.UserPortMax)
	if err != nil {
		t.Fatal(err)
	}
	_ = port

	limiter := ratelimit.New(10, time.Minute)
	t.Cleanup(limiter.Stop)
	logger := logging.New(logging.NewConsoleBackend(io.Discard, "human"))

	collector := stats.NewCollector()
	t.Cleanup(collector.Stop)
	counter := stats.NewTrafficCounter(collector)
	t.Cleanup(counter.Stop)

	h := New(cfg, users, users, users, users, users, acl.AllowAll{}, limiter, logger, counter, nil)
	return h
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// TestPACServedUnauthenticated verifies the PAC endpoint is served without auth
// and hands back the request's own Host as the proxy endpoint (the exact
// host:port the device used), with the configured bypass domains routed DIRECT.
func TestPACServedUnauthenticated(t *testing.T) {
	h := setupProxy(t)
	h.cfg.PACEnabled = true
	h.cfg.PACPath = "/proxy.pac"
	h.cfg.PACBypassDomains = []string{"venmo.com", "paypal.com"}

	req := httptest.NewRequest("GET", "/proxy.pac", nil)
	req.Host = "proxy.chrissnell.com:17001"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("PAC status = %d, want 200 (no auth expected)", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-ns-proxy-autoconfig" {
		t.Errorf("content-type = %q", ct)
	}
	if w.Header().Get("Proxy-Authenticate") != "" {
		t.Error("PAC must not require proxy auth")
	}
	body := w.Body.String()
	if !strings.Contains(body, `return "PROXY proxy.chrissnell.com:17001"`) {
		t.Errorf("PAC did not echo request Host:\n%s", body)
	}
	if !strings.Contains(body, `"venmo.com"`) || !strings.Contains(body, `return "DIRECT"`) {
		t.Errorf("PAC missing bypass rule:\n%s", body)
	}
	// The PAC must never leak credentials.
	for _, bad := range []string{"Basic ", "secret", "Proxy-Authorization"} {
		if strings.Contains(body, bad) {
			t.Errorf("PAC contains %q", bad)
		}
	}
}

// TestPACDisabledFallsThrough verifies that when PAC is off, a GET for the PAC
// path is treated as a normal proxy request (which requires auth → 407).
func TestPACDisabledFallsThrough(t *testing.T) {
	h := setupProxy(t) // PACEnabled defaults to false

	req := httptest.NewRequest("GET", "/proxy.pac", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 407 {
		t.Fatalf("status = %d, want 407 when PAC disabled", w.Code)
	}
}

// TestIOSConnectFlow simulates iOS behavior: CONNECT without auth → 407 → retry with auth on same TCP connection.
func TestIOSConnectFlow(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	handler := setupProxy(t)
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	targetAddr := strings.TrimPrefix(target.URL, "http://")

	// Step 1: CONNECT without auth
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading 407 response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 407 {
		t.Fatalf("expected 407, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Error("missing Proxy-Authenticate header on 407")
	}
	if resp.Header.Get("Proxy-Connection") != "keep-alive" {
		t.Error("missing Proxy-Connection: keep-alive on 407")
	}

	// Step 2: Retry CONNECT with auth on SAME connection
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		targetAddr, targetAddr, basicAuth("alice", "secret"))

	resp, err = http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading 200 response: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Step 3: Send an HTTP request through the tunnel
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr)
	tunnelResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading tunneled response: %v", err)
	}
	body, _ := io.ReadAll(tunnelResp.Body)
	tunnelResp.Body.Close()

	if string(body) != "hello from target" {
		t.Errorf("tunnel body = %q, want 'hello from target'", body)
	}
}

// TestConnectWithAuthOnFirstRequest tests CONNECT with auth provided upfront.
func TestConnectWithAuthOnFirstRequest(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	handler := setupProxy(t)
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	targetAddr := strings.TrimPrefix(target.URL, "http://")
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		targetAddr, targetAddr, basicAuth("alice", "secret"))

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// TestPlainHTTPForward tests plain HTTP forwarding with auth.
func TestPlainHTTPForward(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("Proxy-Authorization should be stripped")
		}
		if r.Header.Get("Proxy-Connection") != "" {
			t.Error("Proxy-Connection should be stripped")
		}
		if r.Header.Get("X-Forwarded-For") != "" {
			t.Error("X-Forwarded-For should not be added")
		}
		w.Header().Set("X-Test", "response")
		w.Write([]byte("forwarded"))
	}))
	defer target.Close()

	handler := setupProxy(t)

	req := httptest.NewRequest("GET", target.URL+"/path", nil)
	req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))
	req.Header.Set("Proxy-Connection", "keep-alive")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "forwarded" {
		t.Errorf("body = %q, want 'forwarded'", w.Body.String())
	}
	if w.Header().Get("X-Test") != "response" {
		t.Error("response header not forwarded")
	}
}

// TestConnectTunnelPropagatesServerClose verifies that when the upstream server
// closes its side of a CONNECT tunnel, the FIN is propagated to the client so a
// response whose body is delimited by connection close terminates cleanly. This
// guards the half-close fix: without it, the client hangs waiting for bytes that
// never arrive — the failure mode that broke connection-reuse-heavy iOS apps.
func TestConnectTunnelPropagatesServerClose(t *testing.T) {
	// Raw target that writes an EOF-delimited HTTP/1.1 response, then closes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		http.ReadRequest(br) // consume the tunneled request
		// No Content-Length: body is delimited by the connection close.
		io.WriteString(c, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ngoodbye")
		c.Close()
	}()

	handler := setupProxy(t)
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	targetAddr := ln.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		targetAddr, targetAddr, basicAuth("alice", "secret"))

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Send a request and read the EOF-delimited response. If the server's FIN
	// is not propagated, the read blocks until this deadline fires.
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr)

	tunnelResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading tunneled response: %v", err)
	}
	body, err := io.ReadAll(tunnelResp.Body)
	tunnelResp.Body.Close()
	if err != nil {
		t.Fatalf("reading body (tunnel likely hung — FIN not propagated): %v", err)
	}
	if string(body) != "goodbye" {
		t.Errorf("body = %q, want 'goodbye'", body)
	}
}

// TestPlainHTTPNoAuth tests that unauthenticated plain HTTP gets 407.
func TestPlainHTTPNoAuth(t *testing.T) {
	handler := setupProxy(t)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 407 {
		t.Fatalf("expected 407, got %d", w.Code)
	}
	if w.Header().Get("Proxy-Authenticate") == "" {
		t.Error("missing Proxy-Authenticate on 407")
	}
}

func TestFormatHeadersRedactsSensitive(t *testing.T) {
	h := http.Header{}
	h.Set("Proxy-Authorization", "Basic c2VjcmV0")
	h.Set("Cookie", "session=abc")
	h.Set("User-Agent", "Venmo/1.0")
	h.Add("Accept", "application/json")

	got := formatHeaders(h)

	if strings.Contains(got, "c2VjcmV0") || strings.Contains(got, "session=abc") {
		t.Errorf("sensitive value leaked: %q", got)
	}
	if !strings.Contains(got, "Proxy-Authorization=<redacted>") {
		t.Errorf("Proxy-Authorization not redacted: %q", got)
	}
	if !strings.Contains(got, "User-Agent=Venmo/1.0") {
		t.Errorf("non-sensitive header missing: %q", got)
	}
	// Keys must be sorted for stable output.
	if strings.Index(got, "Accept=") > strings.Index(got, "User-Agent=") {
		t.Errorf("headers not sorted: %q", got)
	}
}

func TestIsDNSBlocked(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"0.0.0.0", true},
		{"127.0.0.1", true},
		{"127.0.0.53", true},
		{"127.0.53.53", true},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"10.0.0.1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := isDNSBlocked(ip); got != tt.blocked {
			t.Errorf("isDNSBlocked(%s) = %v, want %v", tt.ip, got, tt.blocked)
		}
	}
}

// TestDNSBlockForward tests that DNS-blocked hosts are rejected for plain HTTP.
func TestDNSBlockForward(t *testing.T) {
	handler := setupProxy(t)

	var logBuf bytes.Buffer
	handler.logger = logging.New(logging.NewConsoleBackend(&logBuf, "human"))

	req := httptest.NewRequest("GET", "http://blocked.example.com/tracker.js", nil)
	req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Fatal("expected non-200 for blocked domain")
	}

	logOut := logBuf.String()
	if logOut == "" {
		t.Error("expected log output")
	}
}

// TestResolverFromCtxDefault tests that resolverFromCtx returns the default when no context value.
func TestResolverFromCtxDefault(t *testing.T) {
	handler := setupProxy(t)

	ctx := context.Background()
	r := handler.resolverFromCtx(ctx)
	if r != handler.defaultResolver {
		t.Error("expected default resolver when no context value")
	}
}

// TestResolverFromCtxOverride tests that resolverFromCtx returns the context resolver.
func TestResolverFromCtxOverride(t *testing.T) {
	handler := setupProxy(t)

	customResolver, _ := edns.New("plain", "8.8.8.8:53")
	ctx := context.WithValue(context.Background(), dnsResolverKey, customResolver)

	r := handler.resolverFromCtx(ctx)
	if r != customResolver {
		t.Error("expected custom resolver from context")
	}
}

// TestCtxWithUserDNSNoConfig tests ctxWithUserDNS returns unmodified context for user without DNS.
func TestCtxWithUserDNSNoConfig(t *testing.T) {
	handler := setupProxy(t)

	ctx := context.Background()
	got := handler.ctxWithUserDNS(ctx, "alice")

	if got.Value(dnsResolverKey) != nil {
		t.Error("expected no resolver in context for user without DNS config")
	}
}

// mockDNSGetter is a test helper implementing UserDNSGetter.
type mockDNSGetter struct {
	configs map[string][2]string // username -> [server, protocol]
}

func (m *mockDNSGetter) GetDNS(username string) (string, string) {
	if c, ok := m.configs[username]; ok {
		return c[0], c[1]
	}
	return "", ""
}

// TestCtxWithUserDNSConfigured tests ctxWithUserDNS injects resolver for user with DNS config.
func TestCtxWithUserDNSConfigured(t *testing.T) {
	handler := setupProxy(t)
	handler.dnsGetter = &mockDNSGetter{
		configs: map[string][2]string{
			"alice": {"8.8.8.8:53", "plain"},
		},
	}

	ctx := handler.ctxWithUserDNS(context.Background(), "alice")
	r := ctx.Value(dnsResolverKey)
	if r == nil {
		t.Fatal("expected resolver in context for user with DNS config")
	}
}

// TestCtxWithUserDNSNilGetter tests ctxWithUserDNS gracefully handles nil dnsGetter.
func TestCtxWithUserDNSNilGetter(t *testing.T) {
	handler := setupProxy(t)
	handler.dnsGetter = nil

	ctx := handler.ctxWithUserDNS(context.Background(), "alice")
	if ctx.Value(dnsResolverKey) != nil {
		t.Error("expected no resolver when dnsGetter is nil")
	}
}

// TestPerUserPortAuthRequired tests that CONNECT on a per-user port requires auth (407 without creds).
func TestPerUserPortAuthRequired(t *testing.T) {
	handler := setupProxy(t)
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// CONNECT without credentials
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 407 {
		t.Fatalf("expected 407 for unauthenticated CONNECT, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Error("missing Proxy-Authenticate header on 407")
	}
}

// TestPerUserPortForwardAuthRequired tests that plain HTTP on a per-user port requires auth.
func TestPerUserPortForwardAuthRequired(t *testing.T) {
	handler := setupProxy(t)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	// No Proxy-Authorization header

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 407 {
		t.Fatalf("expected 407 for unauthenticated forward, got %d", w.Code)
	}
}

// TestPerUserPortConnectWithAuth tests CONNECT succeeds with valid credentials.
func TestPerUserPortConnectWithAuth(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tunneled"))
	}))
	defer target.Close()

	handler := setupProxy(t)
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	targetAddr := strings.TrimPrefix(target.URL, "http://")

	// CONNECT with valid credentials
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		targetAddr, targetAddr, basicAuth("alice", "secret"))

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Verify tunnel works
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr)
	tunnelResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading tunneled response: %v", err)
	}
	body, _ := io.ReadAll(tunnelResp.Body)
	tunnelResp.Body.Close()

	if string(body) != "tunneled" {
		t.Errorf("tunnel body = %q, want 'tunneled'", body)
	}
}

// TestPerUserPortBadCredentials tests that invalid credentials are rejected.
func TestPerUserPortBadCredentials(t *testing.T) {
	handler := setupProxy(t)
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// CONNECT with wrong password
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: %s\r\n\r\n",
		basicAuth("alice", "wrongpassword"))

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 407 {
		t.Fatalf("expected 407 for bad credentials, got %d", resp.StatusCode)
	}
}

// TestCtxWithUserDNSInvalidProtocol tests ctxWithUserDNS handles invalid protocol gracefully.
func TestCtxWithUserDNSInvalidProtocol(t *testing.T) {
	handler := setupProxy(t)
	handler.dnsGetter = &mockDNSGetter{
		configs: map[string][2]string{
			"alice": {"1.1.1.1", "invalid"},
		},
	}

	ctx := handler.ctxWithUserDNS(context.Background(), "alice")
	if ctx.Value(dnsResolverKey) != nil {
		t.Error("expected no resolver for invalid protocol")
	}
}

// TestForwardWithPerUserDNS verifies the full flow with per-user DNS through forward.
func TestForwardWithPerUserDNS(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	handler := setupProxy(t)
	handler.dnsGetter = &mockDNSGetter{
		configs: map[string][2]string{
			"alice": {"8.8.8.8:53", "plain"},
		},
	}

	req := httptest.NewRequest("GET", target.URL+"/path", nil)
	req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// buildHandler constructs a Handler with the given config for listener tests.
func buildHandler(t *testing.T, cfg *config.Config) *Handler {
	t.Helper()
	dir := t.TempDir()
	users, err := userdb.Open(filepath.Join(dir, "users.db"),
		logging.New(logging.NewConsoleBackend(io.Discard, "human")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })
	if _, err := users.Add("alice", "secret", cfg.UserPortMin, cfg.UserPortMax); err != nil {
		t.Fatal(err)
	}
	limiter := ratelimit.New(10, time.Minute)
	t.Cleanup(limiter.Stop)
	logger := logging.New(logging.NewConsoleBackend(io.Discard, "human"))
	collector := stats.NewCollector()
	t.Cleanup(collector.Stop)
	counter := stats.NewTrafficCounter(collector)
	t.Cleanup(counter.Stop)
	return New(cfg, users, users, users, users, users, acl.AllowAll{}, limiter, logger, counter, nil)
}

func baseListenerCfg() *config.Config {
	return &config.Config{
		AuthRetryTimeout:   5 * time.Second,
		ConnectDialTimeout: 5 * time.Second,
		IdleTimeout:        30 * time.Second,
		HTTPTimeout:        10 * time.Second,
		DNSProtocol:        "plain",
		UserPortMin:        19081,
		UserPortMax:        19090,
	}
}

// TestDemoModeNoRealListener verifies that with DemoMode enabled, starting a
// user listener registers bookkeeping but never binds a real socket.
func TestDemoModeNoRealListener(t *testing.T) {
	cfg := baseListenerCfg()
	cfg.DemoMode = true
	h := buildHandler(t, cfg)

	const port = 19081
	h.StartListener("alice", port)
	t.Cleanup(func() { h.StopUserListener(port) })

	// Bookkeeping must reflect the port as active for the admin API/reconciler.
	h.portMu.RLock()
	_, tracked := h.userServers[port]
	owner := h.portUsers[port]
	h.portMu.RUnlock()
	if !tracked {
		t.Fatalf("expected port %d to be tracked in userServers", port)
	}
	if owner != "alice" {
		t.Fatalf("expected port %d owner %q, got %q", port, "alice", owner)
	}

	// No real socket should be bound: a dial must fail.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("demo mode: port %d unexpectedly accepted a connection", port)
	}
}

// TestNonDemoModeBindsListener is the control: without DemoMode, a real socket
// is bound and accepts connections.
func TestNonDemoModeBindsListener(t *testing.T) {
	cfg := baseListenerCfg()
	h := buildHandler(t, cfg)

	const port = 19082
	h.StartListener("alice", port)
	t.Cleanup(func() { h.StopUserListener(port) })

	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("expected port %d to accept a connection, got %v", port, err)
	}
	conn.Close()
}
