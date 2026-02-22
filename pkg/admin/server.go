package admin

import (
	"embed"
	"io/fs"
	"net/http"
	"time"

	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

//go:embed static/*
var staticFS embed.FS

// Server is the admin HTTP handler.
type Server struct {
	mux *http.ServeMux
}

func NewServer(adminAuth *auth.AdminAuth, state *ProxyState, collector *stats.Collector, users *userdb.DB) *Server {
	sessions := NewSessionStore(1 * time.Hour)
	a := &api{
		auth:     adminAuth,
		state:    state,
		sessions: sessions,
		stats:    collector,
		users:    users,
	}

	mux := http.NewServeMux()

	// Static files (CSS, fonts)
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// API routes
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/logout", a.handleLogout)
	mux.HandleFunc("/api/status", a.requireSession(a.handleStatus))
	mux.HandleFunc("/api/proxy/toggle", a.requireSession(a.handleToggle))
	mux.HandleFunc("/api/stats/top-sites", a.requireSession(a.handleTopSites))
	mux.HandleFunc("/api/stats/top-blocked", a.requireSession(a.handleTopBlocked))
	mux.HandleFunc("/api/stats/traffic", a.requireSession(a.handleTraffic))
	mux.HandleFunc("/api/logs", a.requireSession(a.handleLogs))
	mux.HandleFunc("/api/users", a.requireSession(a.handleUsers))
	mux.HandleFunc("/api/users/password", a.requireSession(a.handleChangePassword))

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
