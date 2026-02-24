package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"evan-proxy/pkg/userdb"
)

func setupAPI(t *testing.T) *api {
	t.Helper()
	dir := t.TempDir()
	users, err := userdb.Open(filepath.Join(dir, "users.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })
	if err := users.Add("alice", "secret"); err != nil {
		t.Fatal(err)
	}

	return &api{
		sessions: NewSessionStore(1 * time.Hour),
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
