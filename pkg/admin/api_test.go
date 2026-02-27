package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/userdb"
)

func setupAPI(t *testing.T) *api {
	t.Helper()
	dir := t.TempDir()
	lg := logging.New(logging.NewConsoleBackend(io.Discard, "human"))
	users, err := userdb.Open(filepath.Join(dir, "users.db"), "", lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })
	if _, err := users.Add("alice", "secret", 8081, 8090); err != nil {
		t.Fatal(err)
	}

	sessions, err := NewSessionStore(filepath.Join(dir, "sessions.db"), 1*time.Hour, lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sessions.Stop() })

	return &api{
		sessions: sessions,
		users:    users,
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
