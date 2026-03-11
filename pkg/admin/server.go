package admin

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/pprof"
	"time"

	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/metrics"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

//go:embed static/*
var staticFS embed.FS

// Server is the admin HTTP handler.
type Server struct {
	mux *http.ServeMux
}

func NewServer(adminAuth *auth.AdminAuth, collector *stats.Collector, users *userdb.DB, ports PortManager, m *metrics.Metrics, lg *logging.Logger, version string) *Server {
	sessions := NewSessionStore(24*time.Hour, lg)
	a := &api{
		auth:     adminAuth,
		sessions: sessions,
		stats:    collector,
		users:    users,
		ports:    ports,
		logger:   lg,
	}

	mux := http.NewServeMux()

	// Static files (CSS, fonts)
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// API routes
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/logout", a.handleLogout)
	mux.HandleFunc("/api/stats/top-sites", a.requireSession(a.handleTopSites))
	mux.HandleFunc("/api/stats/top-blocked", a.requireSession(a.handleTopBlocked))
	mux.HandleFunc("/api/stats/traffic", a.requireSession(a.handleTraffic))
	mux.HandleFunc("/api/logs", a.requireSession(a.handleLogs))
	mux.HandleFunc("/api/users", a.requireSession(a.handleUsers))
	mux.HandleFunc("/api/users/password", a.requireSession(a.handleChangePassword))
	mux.HandleFunc("/api/users/port", a.requireSession(a.handleUpdatePort))
	mux.HandleFunc("/api/users/dns", a.requireSession(a.handleUpdateDNS))
	mux.HandleFunc("/api/users/dns/test", a.requireSession(a.handleTestDNS))
	mux.HandleFunc("/api/users/enabled", a.requireSession(a.handleSetEnabled))
	mux.HandleFunc("/api/users/downtime", a.requireSession(a.handleUpdateDowntime))

	// Version (no auth)
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":%q}`, version)
	})

	// Prometheus metrics (no auth — standard for scraping)
	mux.Handle("/metrics", m.Handler())

	// pprof debug endpoints (no auth — admin port is internal-only)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// Pages
	mux.HandleFunc("/login", serveFile("static/login.html"))
	mux.HandleFunc("/", a.requireSessionPage(serveFile("static/index.html")))

	return &Server{mux: mux}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func serveFile(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile(name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}
}

// requireSessionPage redirects to /login if no valid session.
func (a *api) requireSessionPage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || !a.sessions.Validate(c.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}
