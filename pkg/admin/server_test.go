package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/metrics"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

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
	m := metrics.New(metrics.Options{})

	opts := Options{LoginRateLimit: 5, LoginWindow: time.Minute, LoginGlobalMax: 100}
	// mountDiagnostics=false: /metrics is served on a dedicated listener, never
	// the admin mux, in these tests.
	return NewServer(adminAuth, collector, users, newMockPortManager(), m, lg, "test", opts, false, forceHTTPS)
}

// TestServer_PprofNotExposed asserts the pprof debug endpoints are not
// registered on the admin mux. With the handlers removed, these paths fall
// through to the catch-all "/" page, which redirects unauthenticated requests
// to /login — the same response any unregistered path gets. If pprof were still
// wired up it would answer 200 with profiling data instead.
func TestServer_PprofNotExposed(t *testing.T) {
	srv := newTestServer(t, false)
	for _, path := range []string{
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/profile",
		"/debug/pprof/symbol",
		"/debug/pprof/trace",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Fatalf("pprof must not be served on admin mux; %s got %d (Location=%q), want 303 -> /login",
				path, w.Code, w.Header().Get("Location"))
		}
		// Belt and suspenders: the response must not be the pprof handler's
		// output, independent of how the catch-all page happens to respond.
		if body := w.Body.String(); strings.Contains(body, "Types of profiles available") {
			t.Fatalf("pprof handler output leaked on admin mux at %s", path)
		}
	}
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

// Full pairing flow through the assembled server: login -> enroll -> pair ->
// bearer-authenticated /api/users -> revoke -> 401.
func TestServerDevicePairingFlow(t *testing.T) {
	srv := newTestServer(t, false)

	do := func(req *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	// Admin logs in.
	w := do(httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200", w.Code)
	}
	session := w.Result().Cookies()[0]

	// Enrollment requires the session.
	if w = do(httptest.NewRequest(http.MethodPost, "/api/devices/enroll", nil)); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated enroll = %d, want 401", w.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/devices/enroll", nil)
	req.AddCookie(session)
	w = do(req)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll = %d, want 200", w.Code)
	}
	var enr struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(w.Body).Decode(&enr); err != nil {
		t.Fatal(err)
	}

	// Device pairs without any session.
	w = do(httptest.NewRequest(http.MethodPost, "/api/pair", strings.NewReader(`{"code":"`+enr.Code+`","device_name":"phone"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("pair = %d, want 200", w.Code)
	}
	var pair struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&pair); err != nil {
		t.Fatal(err)
	}

	// The bearer token authenticates a protected route with no cookie.
	req = httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+pair.Token)
	if w = do(req); w.Code != http.StatusOK {
		t.Fatalf("bearer /api/users = %d, want 200", w.Code)
	}

	// But it must NOT manage devices — enroll and list/revoke are session-only,
	// so a leaked token cannot mint a replacement or revoke other devices.
	req = httptest.NewRequest(http.MethodPost, "/api/devices/enroll", nil)
	req.Header.Set("Authorization", "Bearer "+pair.Token)
	if w = do(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("bearer enroll = %d, want 401", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+pair.Token)
	if w = do(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("bearer list devices = %d, want 401", w.Code)
	}

	// Revoke the device; the token stops working.
	req = httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.AddCookie(session)
	w = do(req)
	var devices []userdb.DeviceToken
	if err := json.NewDecoder(w.Body).Decode(&devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("want 1 device, got %d", len(devices))
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/devices?id="+devices[0].ID, nil)
	req.AddCookie(session)
	if w = do(req); w.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+pair.Token)
	if w = do(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer /api/users = %d, want 401", w.Code)
	}
}
