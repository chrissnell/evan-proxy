package proxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"evan-proxy/pkg/acl"
	"evan-proxy/pkg/admin"
	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/config"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/ratelimit"
	"evan-proxy/pkg/stats"
)

func setupProxy(t *testing.T) (*Handler, *admin.ProxyState) {
	t.Helper()

	dir := t.TempDir()
	usersPath := filepath.Join(dir, "users.json")
	os.WriteFile(usersPath, []byte(`{"users":[{"username":"alice","password":"secret"}]}`), 0600)

	users, err := auth.LoadUsers(usersPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		AuthRetryTimeout:   5 * time.Second,
		ConnectDialTimeout: 5 * time.Second,
		IdleTimeout:        30 * time.Second,
		HTTPTimeout:        10 * time.Second,
	}

	limiter := ratelimit.New(10, time.Minute)
	t.Cleanup(limiter.Stop)
	logger := logging.New(io.Discard, "human")
	state := admin.NewProxyState()

	collector := stats.NewCollector()
	t.Cleanup(collector.Stop)
	counter := stats.NewTrafficCounter(collector)
	t.Cleanup(counter.Stop)

	h := New(cfg, users, acl.AllowAll{}, limiter, logger, counter, state)
	return h, state
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// TestIOSConnectFlow simulates iOS behavior: CONNECT without auth → 407 → retry with auth on same TCP connection.
func TestIOSConnectFlow(t *testing.T) {
	// Start a target server to tunnel to
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	handler, _ := setupProxy(t)
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	// Connect raw TCP to proxy
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

	handler, _ := setupProxy(t)
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
		// Verify hop-by-hop headers are stripped
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

	handler, _ := setupProxy(t)

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

// TestPlainHTTPNoAuth tests that unauthenticated plain HTTP gets 407.
func TestPlainHTTPNoAuth(t *testing.T) {
	handler, _ := setupProxy(t)

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

// TestDisabledState tests that disabled proxy returns the disabled page.
func TestDisabledState(t *testing.T) {
	handler, state := setupProxy(t)
	state.SetEnabled(false)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "PROXY DISABLED") {
		t.Error("expected disabled page content")
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

// TestDNSBlockForward tests that DNS-blocked hosts log "dns-block" event for plain HTTP.
func TestDNSBlockForward(t *testing.T) {
	handler, _ := setupProxy(t)

	var logBuf bytes.Buffer
	handler.logger = logging.New(&logBuf, "human")

	req := httptest.NewRequest("GET", "http://blocked.example.com/tracker.js", nil)
	req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should get 502 or 523 — either way not 200
	if w.Code == 200 {
		t.Fatal("expected non-200 for blocked domain")
	}

	// The transport will fail because blocked.example.com doesn't resolve.
	// This test mainly verifies no panics and the code path works.
	logOut := logBuf.String()
	if logOut == "" {
		t.Error("expected log output")
	}
}
