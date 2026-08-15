package admin

import (
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/metrics"
	"evan-proxy/pkg/ratelimit"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

//go:embed static/*
var staticFS embed.FS

// Server is the admin HTTP handler.
type Server struct {
	handler http.Handler
}

// Options carries the login brute-force protection settings into the admin
// server. TrustedProxies is the parsed form of cfg.TrustedProxyCIDRs.
type Options struct {
	LoginRateLimit int
	LoginWindow    time.Duration
	LoginGlobalMax int
	TrustedProxies []*net.IPNet
	// DemoMode makes device enrollment codes persistent and reusable so the
	// pairing QR can be handed to App Store review. See enrollStore.
	DemoMode bool
}

// NewServer builds the admin HTTP handler. mountDiagnostics mounts /metrics on
// the admin port when no dedicated internal metrics listener is configured.
// forceHTTPS sets the Secure flag on session cookies and emits HSTS — enable it
// when TLS terminates in front (ingress) or in-process (autocert).
func NewServer(adminAuth *auth.AdminAuth, collector *stats.Collector, users *userdb.DB, ports PortManager, m *metrics.Metrics, lg *logging.Logger, version string, opts Options, mountDiagnostics bool, forceHTTPS bool) *Server {
	sessions := NewSessionStore(24*time.Hour, lg)
	a := &api{
		auth:            adminAuth,
		sessions:        sessions,
		stats:           collector,
		users:           users,
		ports:           ports,
		logger:          lg,
		loginLimiter:    ratelimit.New(opts.LoginRateLimit, opts.LoginWindow),
		trustedProxies:  opts.TrustedProxies,
		globalFails:     newGlobalCounter(opts.LoginGlobalMax, opts.LoginWindow),
		loginRetryAfter: strconv.Itoa(int(opts.LoginWindow.Seconds())),
		secureCookies:   forceHTTPS,
		enroll:          newEnrollStore(5*time.Minute, opts.DemoMode),
		demoMode:        opts.DemoMode,
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
	mux.HandleFunc("/api/users/downtime-override", a.requireSession(a.handleDowntimeOverride))

	// Device pairing: enroll/list/revoke require the browser session (a device
	// bearer token must not be able to mint or revoke tokens); /api/pair is
	// public but gated by the single-use enrollment code.
	mux.HandleFunc("/api/devices/enroll", a.requireAdminSession(a.handleEnroll))
	mux.HandleFunc("/api/devices", a.requireAdminSession(a.handleDevices))
	mux.HandleFunc("/api/pair", a.handlePair)

	// Version (no auth)
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":%q}`, version)
	})

	// Prometheus /metrics is mounted on the admin port only when no dedicated
	// internal metrics listener is configured (mountDiagnostics). Otherwise it is
	// served on the internal listener (see cmd/evan-proxy/main.go). pprof is never
	// mounted on the admin mux — it is opt-in on its own loopback listener.
	if mountDiagnostics {
		mux.Handle("/metrics", m.Handler())
	}

	// Pages
	mux.HandleFunc("/login", serveFile("static/login.html"))
	mux.HandleFunc("/", a.requireSessionPage(serveFile("static/index.html")))

	return &Server{handler: securityHeaders(mux, forceHTTPS)}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// RegisterPprof mounts the net/http/pprof debug endpoints on mux. These are
// unauthenticated and expose process internals (argv, heap/CPU profiles), so
// they belong on an internal-only listener — never the public admin host.
func RegisterPprof(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
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
