package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/metrics"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	lg := logging.New(logging.NewConsoleBackend(io.Discard, "human"))
	users, err := userdb.Open(filepath.Join(dir, "users.db"), lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })

	adminAuth := auth.NewAdminAuth("admin", "")
	collector := stats.NewCollector()
	t.Cleanup(collector.Stop)
	m := metrics.New()

	return NewServer(adminAuth, collector, users, newMockPortManager(), m, lg, "test")
}

// TestServer_PprofNotExposed asserts the pprof debug endpoints are not
// registered on the admin mux. With the handlers removed, these paths fall
// through to the catch-all "/" page, which redirects unauthenticated requests
// to /login — the same response any unregistered path gets. If pprof were still
// wired up it would answer 200 with profiling data instead.
func TestServer_PprofNotExposed(t *testing.T) {
	srv := newTestServer(t)
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
	}
}
