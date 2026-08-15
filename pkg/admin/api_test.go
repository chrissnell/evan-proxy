package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/ratelimit"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"

	"golang.org/x/crypto/bcrypt"
)

func mustBcrypt(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func setupAPI(t *testing.T) *api {
	t.Helper()
	dir := t.TempDir()
	lg := logging.New(logging.NewConsoleBackend(io.Discard, "human"))
	users, err := userdb.Open(filepath.Join(dir, "users.db"), lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })
	if _, err := users.Add("alice", "secret", 8081, 8090); err != nil {
		t.Fatal(err)
	}

	sessions := NewSessionStore(1*time.Hour, lg)
	t.Cleanup(func() { sessions.Stop() })

	limiter := ratelimit.New(3, time.Minute)
	t.Cleanup(func() { limiter.Stop() })

	enroll := newEnrollStore(5*time.Minute, false)
	t.Cleanup(enroll.Stop)

	return &api{
		auth:            auth.NewAdminAuth("admin", mustBcrypt(t, "correct-horse")),
		sessions:        sessions,
		users:           users,
		logger:          lg,
		loginLimiter:    limiter,
		globalFails:     newGlobalCounter(100, time.Minute),
		loginRetryAfter: "60",
		enroll:          enroll,
	}
}

func TestHandleLogin_RateLimitsAfterFailures(t *testing.T) {
	a := setupAPI(t)
	body := `{"username":"admin","password":"wrong"}`
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
		req.RemoteAddr = "203.0.113.7:1111"
		w := httptest.NewRecorder()
		a.handleLogin(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, w.Code)
		}
	}
	// 4th attempt (even with correct password) is blocked by the limiter.
	req := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"admin","password":"correct-horse"}`))
	req.RemoteAddr = "203.0.113.7:1111"
	w := httptest.NewRecorder()
	a.handleLogin(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after limit, got %d", w.Code)
	}
}

func TestHandleLogin_FreshIPSucceeds(t *testing.T) {
	a := setupAPI(t)
	// Exhaust the limiter for one IP.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login",
			strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.RemoteAddr = "203.0.113.7:1111"
		a.handleLogin(httptest.NewRecorder(), req)
	}
	// A different IP with the correct password still logs in.
	req := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"admin","password":"correct-horse"}`))
	req.RemoteAddr = "198.51.100.4:2222"
	w := httptest.NewRecorder()
	a.handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("fresh IP want 200, got %d", w.Code)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("expected a session cookie to be set")
	}
}

func TestHandleLogin_GlobalCeilingTrips(t *testing.T) {
	a := setupAPI(t)
	// Tight global ceiling; per-IP limiter is generous so only the global
	// ceiling can be the thing that trips.
	a.loginLimiter = ratelimit.New(1000, time.Minute)
	t.Cleanup(func() { a.loginLimiter.Stop() })
	a.globalFails = newGlobalCounter(3, time.Minute)

	// Three failures from rotating IPs exhaust the global ceiling.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login",
			strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.RemoteAddr = fmt.Sprintf("203.0.113.%d:1111", i+1)
		w := httptest.NewRecorder()
		a.handleLogin(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, w.Code)
		}
	}
	// A brand-new IP with the correct password is now blocked by the ceiling.
	req := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"admin","password":"correct-horse"}`))
	req.RemoteAddr = "198.51.100.9:2222"
	w := httptest.NewRecorder()
	a.handleLogin(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 from global ceiling, got %d", w.Code)
	}
}

func TestHandleLogin_TrustedProxyKeysOnForwardedIP(t *testing.T) {
	a := setupAPI(t)
	a.trustedProxies = []*net.IPNet{mustCIDR("10.0.0.0/8")}

	// All requests share the same trusted peer but forward distinct clients.
	// Exhaust the limiter for one forwarded client (limit is 3).
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login",
			strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.RemoteAddr = "10.0.0.5:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.50")
		w := httptest.NewRecorder()
		a.handleLogin(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, w.Code)
		}
	}
	// Same trusted peer, but a different forwarded client still gets through.
	req := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"admin","password":"correct-horse"}`))
	req.RemoteAddr = "10.0.0.5:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.51")
	w := httptest.NewRecorder()
	a.handleLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("distinct forwarded client want 200, got %d", w.Code)
	}

	// The exhausted forwarded client is blocked even with the right password.
	req = httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"admin","password":"correct-horse"}`))
	req.RemoteAddr = "10.0.0.5:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	w = httptest.NewRecorder()
	a.handleLogin(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("exhausted forwarded client want 429, got %d", w.Code)
	}
}

func TestHandleLogin_429SetsRetryAfter(t *testing.T) {
	a := setupAPI(t)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login",
			strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.RemoteAddr = "203.0.113.7:1111"
		a.handleLogin(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"admin","password":"wrong"}`))
	req.RemoteAddr = "203.0.113.7:1111"
	w := httptest.NewRecorder()
	a.handleLogin(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After = %q, want 60", got)
	}
}

func TestHandleLogin_SuccessDoesNotCount(t *testing.T) {
	a := setupAPI(t)
	// Repeated successful logins from one IP must never trip the limiter,
	// so the iOS reauth path stays functional.
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login",
			strings.NewReader(`{"username":"admin","password":"correct-horse"}`))
		req.RemoteAddr = "203.0.113.8:3333"
		w := httptest.NewRecorder()
		a.handleLogin(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: want 200, got %d", i, w.Code)
		}
	}
}

func TestHandleUpdateDNS_MethodNotAllowed(t *testing.T) {
	a := setupAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/users/dns", nil)
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleUpdateDNS_BadJSON(t *testing.T) {
	a := setupAPI(t)
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdateDNS_MissingUsername(t *testing.T) {
	a := setupAPI(t)
	body := `{"dns_server":"8.8.8.8:53","dns_protocol":"plain"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdateDNS_InvalidProtocol(t *testing.T) {
	a := setupAPI(t)
	body := `{"username":"alice","dns_server":"8.8.8.8:53","dns_protocol":"quic"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdateDNS_UnknownUser(t *testing.T) {
	a := setupAPI(t)
	body := `{"username":"nobody","dns_server":"8.8.8.8:53","dns_protocol":"plain"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleUpdateDNS_Success(t *testing.T) {
	a := setupAPI(t)
	body := `{"username":"alice","dns_server":"1.1.1.1:853","dns_protocol":"tls"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify DNS was actually set.
	server, proto := a.users.GetDNS("alice")
	if server != "1.1.1.1:853" || proto != "tls" {
		t.Errorf("DNS not saved: server=%q proto=%q", server, proto)
	}
}

func TestHandleUpdateDNS_ClearDNS(t *testing.T) {
	a := setupAPI(t)

	// Set DNS first.
	if err := a.users.UpdateDNS("alice", "8.8.8.8:53", "plain"); err != nil {
		t.Fatal(err)
	}

	// Clear it via API.
	body := `{"username":"alice","dns_server":"","dns_protocol":""}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	server, proto := a.users.GetDNS("alice")
	if server != "" || proto != "" {
		t.Errorf("DNS not cleared: server=%q proto=%q", server, proto)
	}
}

func TestHandleUpdateDNS_DefaultPortTLS(t *testing.T) {
	a := setupAPI(t)
	body := `{"username":"alice","dns_server":"1.1.1.1","dns_protocol":"tls"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	server, _ := a.users.GetDNS("alice")
	if server != "1.1.1.1:853" {
		t.Errorf("expected 1.1.1.1:853, got %q", server)
	}
}

func TestHandleUpdateDNS_DefaultPortPlain(t *testing.T) {
	a := setupAPI(t)
	body := `{"username":"alice","dns_server":"8.8.8.8","dns_protocol":"plain"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	server, _ := a.users.GetDNS("alice")
	if server != "8.8.8.8:53" {
		t.Errorf("expected 8.8.8.8:53, got %q", server)
	}
}

func TestHandleUpdateDNS_HTTPSPrefix(t *testing.T) {
	a := setupAPI(t)
	body := `{"username":"alice","dns_server":"1.1.1.1/dns-query","dns_protocol":"https"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/dns", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdateDNS(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	server, _ := a.users.GetDNS("alice")
	if server != "https://1.1.1.1/dns-query" {
		t.Errorf("expected https://1.1.1.1/dns-query, got %q", server)
	}
}

func TestHandleTestDNS_MethodNotAllowed(t *testing.T) {
	a := setupAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/users/dns/test", nil)
	w := httptest.NewRecorder()
	a.handleTestDNS(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleTestDNS_BadProtocol(t *testing.T) {
	a := setupAPI(t)
	body := `{"dns_server":"8.8.8.8","dns_protocol":"quic"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users/dns/test", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleTestDNS(w, req)

	var resp dnsTestResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.OK {
		t.Fatal("expected ok=false for invalid protocol")
	}
	if resp.Error == "" {
		t.Error("expected error message")
	}
}

func TestHandleTestDNS_Success(t *testing.T) {
	a := setupAPI(t)
	body := `{"dns_server":"8.8.8.8:53","dns_protocol":"plain"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users/dns/test", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleTestDNS(w, req)

	var resp dnsTestResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp.OK {
		t.Fatalf("expected ok=true, got error: %s", resp.Error)
	}
	if len(resp.Addresses) == 0 {
		t.Error("expected at least one address")
	}
}

// mockPortManager implements PortManager for testing.
type mockPortManager struct {
	ports    map[string]int // username → port
	minPort  int
	maxPort  int
	updateFn func(username string, port int) error
}

func newMockPortManager() *mockPortManager {
	return &mockPortManager{
		ports:   make(map[string]int),
		minPort: 8081,
		maxPort: 8090,
	}
}

func (m *mockPortManager) UpdateUserPort(username string, port int) error {
	if m.updateFn != nil {
		return m.updateFn(username, port)
	}
	if port == 0 {
		delete(m.ports, username)
	} else {
		m.ports[username] = port
	}
	return nil
}

func (m *mockPortManager) UserPortRange() (int, int) {
	return m.minPort, m.maxPort
}

func (m *mockPortManager) StartListener(username string, port int) {}
func (m *mockPortManager) StopListener(port int)                   {}

func TestHandleUpdatePort_MethodNotAllowed(t *testing.T) {
	a := setupAPI(t)
	a.ports = newMockPortManager()
	req := httptest.NewRequest(http.MethodGet, "/api/users/port", nil)
	w := httptest.NewRecorder()
	a.handleUpdatePort(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleUpdatePort_BadJSON(t *testing.T) {
	a := setupAPI(t)
	a.ports = newMockPortManager()
	req := httptest.NewRequest(http.MethodPut, "/api/users/port", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	a.handleUpdatePort(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdatePort_MissingUsername(t *testing.T) {
	a := setupAPI(t)
	a.ports = newMockPortManager()
	body := `{"port":8081}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/port", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdatePort(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdatePort_OutOfRange(t *testing.T) {
	a := setupAPI(t)
	a.ports = newMockPortManager()
	body := `{"username":"alice","port":9999}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/port", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdatePort(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdatePort_PortConflict(t *testing.T) {
	a := setupAPI(t)
	a.ports = newMockPortManager()
	// Assign port 8081 to alice first via DB
	if err := a.users.UpdatePort("alice", 8081); err != nil {
		t.Fatal(err)
	}

	// Add bob
	if _, err := a.users.Add("bob", "secret2", 8081, 8090); err != nil {
		t.Fatal(err)
	}

	// Try to assign the same port to bob
	body := `{"username":"bob","port":8081}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/port", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdatePort(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

func TestHandleUpdatePort_Success(t *testing.T) {
	a := setupAPI(t)
	a.ports = newMockPortManager()
	body := `{"username":"alice","port":8081}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/port", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdatePort(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandleUpdatePort_ClearPort(t *testing.T) {
	a := setupAPI(t)
	a.ports = newMockPortManager()
	// Assign port first
	if err := a.users.UpdatePort("alice", 8081); err != nil {
		t.Fatal(err)
	}

	// Clear it
	body := `{"username":"alice","port":0}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/port", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdatePort(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandleUpdatePort_UnknownUser(t *testing.T) {
	a := setupAPI(t)
	pm := newMockPortManager()
	pm.updateFn = func(username string, port int) error {
		return fmt.Errorf("%w: %q", userdb.ErrUnknownUser, username)
	}
	a.ports = pm
	body := `{"username":"nobody","port":8089}`
	req := httptest.NewRequest(http.MethodPut, "/api/users/port", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.handleUpdatePort(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestNormalizeDNSServer(t *testing.T) {
	tests := []struct {
		server, proto, want string
	}{
		{"1.1.1.1", "tls", "1.1.1.1:853"},
		{"1.1.1.1:853", "tls", "1.1.1.1:853"},
		{"8.8.8.8", "plain", "8.8.8.8:53"},
		{"8.8.8.8:53", "plain", "8.8.8.8:53"},
		{"1.1.1.1/dns-query", "https", "https://1.1.1.1/dns-query"},
		{"https://1.1.1.1/dns-query", "https", "https://1.1.1.1/dns-query"},
	}
	for _, tt := range tests {
		got := normalizeDNSServer(tt.server, tt.proto)
		if got != tt.want {
			t.Errorf("normalizeDNSServer(%q, %q) = %q, want %q", tt.server, tt.proto, got, tt.want)
		}
	}
}

// TestHandleLogs_FlushesHeadersImmediately verifies the SSE stream establishes
// (status + an initial frame) before any log event, so a client on a quiet
// server (e.g. the no-traffic demo) isn't left hanging with no response.
func TestHandleLogs_FlushesHeadersImmediately(t *testing.T) {
	a := setupAPI(t)
	a.stats = stats.NewCollector()
	t.Cleanup(a.stats.Stop)

	// Pre-cancel: handleLogs writes+flushes the initial frame before entering
	// its select loop, then returns as soon as it sees the cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/logs", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	a.handleLogs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), ": connected") {
		t.Fatalf("expected an initial ': connected' SSE frame before any event, got %q", rec.Body.String())
	}
}
