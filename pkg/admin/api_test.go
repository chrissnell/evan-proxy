package admin

import (
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
