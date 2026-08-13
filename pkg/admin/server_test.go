package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/metrics"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

// metrics.New() registers on the global Prometheus registry, so it can only be
// called once per process — share one instance across tests.
var (
	testMetricsOnce sync.Once
	testMetricsInst *metrics.Metrics
)

func testMetrics() *metrics.Metrics {
	testMetricsOnce.Do(func() { testMetricsInst = metrics.New() })
	return testMetricsInst
}

func newTestServer(t *testing.T, forceHTTPS bool) *Server {
	t.Helper()
	dir := t.TempDir()
	lg := logging.New(logging.NewConsoleBackend(io.Discard, "human"))
	users, err := userdb.Open(filepath.Join(dir, "users.db"), lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	adminAuth := auth.NewAdminAuth("admin", string(hash))
	collector := stats.NewCollector()
	t.Cleanup(collector.Stop)

	return NewServer(adminAuth, collector, users, newMockPortManager(), testMetrics(), lg, "test", forceHTTPS)
}

// Login through the assembled server must set a Secure cookie when forceHTTPS is
// on, proving secureCookies is plumbed from NewServer into handleLogin.
func TestServerLoginSecureCookie(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie set on login")
	}
	c := cookies[0]
	if c.Name != sessionCookie || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected secure httponly strict session cookie, got %+v", c)
	}
}

func TestServerLoginInsecureCookie(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200", w.Code)
	}
	if c := w.Result().Cookies()[0]; c.Secure {
		t.Fatalf("expected Secure=false when forceHTTPS off, got %+v", c)
	}
}

// The security-headers middleware must apply to responses served through the
// mux, and HSTS must track forceHTTPS.
func TestServerSecurityHeaders(t *testing.T) {
	for _, tc := range []struct {
		name       string
		forceHTTPS bool
		wantHSTS   bool
	}{
		{"https", true, true},
		{"plain", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, tc.forceHTTPS)
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			hsts := w.Header().Get("Strict-Transport-Security")
			if tc.wantHSTS && hsts == "" {
				t.Errorf("expected HSTS header, got none")
			}
			if !tc.wantHSTS && hsts != "" {
				t.Errorf("expected no HSTS header, got %q", hsts)
			}
		})
	}
}
