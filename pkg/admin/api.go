package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"evan-proxy/pkg/auth"
	edns "evan-proxy/pkg/dns"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/ratelimit"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

// PortManager controls per-user dedicated proxy port listeners.
type PortManager interface {
	UpdateUserPort(username string, port int) error
	UserPortRange() (min, max int)
	StartListener(username string, port int)
	StopListener(port int)
}

type api struct {
	auth            *auth.AdminAuth
	sessions        *SessionStore
	stats           *stats.Collector
	users           *userdb.DB
	ports           PortManager
	logger          *logging.Logger
	loginLimiter    *ratelimit.Limiter
	trustedProxies  []*net.IPNet
	globalFails     *globalCounter // shared global failure ceiling
	loginRetryAfter string         // Retry-After header value (seconds) for 429s
	secureCookies   bool
	enroll          *enrollStore // single-use device enrollment codes
	demoMode        bool         // App Store demo: no-op instance; see requireSession
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *api) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Gate the attempt on the per-IP sliding-window limiter and the global
	// failure ceiling before doing any work. Only failures are recorded, so a
	// device that keeps logging in successfully (the iOS reauth path) never
	// trips the limiter.
	ip := clientIP(r, a.trustedProxies)
	if !a.loginLimiter.Allow(ip) || !a.globalFails.allow() {
		if a.loginRetryAfter != "" {
			w.Header().Set("Retry-After", a.loginRetryAfter)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := a.auth.Check(req.Username, req.Password); err != nil {
		a.loginLimiter.RecordFailure(ip)
		a.globalFails.record()
		a.logger.Errorf("admin", "login failed from %s: %v", ip, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := a.sessions.Create()
	http.SetCookie(w, sessionCookieFor(token, a.secureCookies))
	w.WriteHeader(http.StatusOK)
}

func (a *api) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessions.Delete(c.Value)
	}
	http.SetCookie(w, clearedSessionCookie(a.secureCookies))
	w.WriteHeader(http.StatusOK)
}

// authed reports whether the request carries a valid session cookie (browser)
// or a valid device bearer token (paired app).
func (a *api) authed(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if _, ok := a.users.ValidateDeviceToken(strings.TrimPrefix(h, "Bearer ")); ok {
			return true
		}
	}
	if c, err := r.Cookie(sessionCookie); err == nil && a.sessions.Validate(c.Value) {
		return true
	}
	return false
}

// requireSession wraps a handler with authentication: session cookie or
// device bearer token.
//
// Demo mode is a deliberate exception: the App Store validation build is a
// no-op instance (no real proxying, fake users), and its whole purpose is to
// let Apple exercise the app end to end. It serves these read/manage endpoints
// without requiring auth so a paired app that fails to attach its token never
// gets a 401 and never gets bounced back to pairing. Never enabled in a real
// deployment. Device management (requireAdminSession) stays cookie-gated.
func (a *api) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.demoMode && !a.authed(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requireAdminSession accepts only the browser session cookie, never a device
// bearer token. Device management stays session-only so a leaked token cannot
// enroll a replacement for itself or revoke other devices — revoking a token
// must be a complete kill.
func (a *api) requireAdminSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || !a.sessions.Validate(c.Value) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (a *api) handleTopSites(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.stats.TopHosts(10))
}

func (a *api) handleTopBlocked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.stats.TopBlocked(10))
}

func (a *api) handleTraffic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.stats.Traffic(60))
}

func (a *api) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.handleListUsers(w, r)
	case http.MethodPost:
		a.handleCreateUser(w, r)
	case http.MethodDelete:
		a.handleDeleteUser(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *api) handleListUsers(w http.ResponseWriter, _ *http.Request) {
	users, err := a.users.List()
	if err != nil {
		a.logger.Errorf("admin", "list users: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (a *api) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}

	min, max := a.ports.UserPortRange()
	port, err := a.users.Add(req.Username, req.Password, min, max)
	if err != nil {
		if errors.Is(err, userdb.ErrUserExists) {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}
		if errors.Is(err, userdb.ErrNoPortAvailable) {
			http.Error(w, "no ports available", http.StatusConflict)
			return
		}
		a.logger.Errorf("admin", "create user: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Start the per-user port listener
	if err := a.ports.UpdateUserPort(req.Username, port); err != nil {
		a.logger.Errorf("admin", "start user listener: %v", err)
	}

	w.WriteHeader(http.StatusCreated)
}

func (a *api) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Stop the user's port listener before deleting
	users, _ := a.users.List()
	for _, u := range users {
		if u.Username == username && u.Port > 0 {
			a.ports.UpdateUserPort(username, 0)
			break
		}
	}

	if err := a.users.Delete(username); err != nil {
		if errors.Is(err, userdb.ErrUnknownUser) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		a.logger.Errorf("admin", "delete user: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (a *api) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}

	if err := a.users.ChangePassword(req.Username, req.Password); err != nil {
		if errors.Is(err, userdb.ErrUnknownUser) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		a.logger.Errorf("admin", "change password: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type portRequest struct {
	Username string `json:"username"`
	Port     int    `json:"port"`
}

func (a *api) handleUpdatePort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req portRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Validate port range (0 means unassign)
	if req.Port != 0 {
		min, max := a.ports.UserPortRange()
		if req.Port < min || req.Port > max {
			http.Error(w, fmt.Sprintf("port must be between %d and %d", min, max), http.StatusBadRequest)
			return
		}
		// Check if port is already assigned to a different user
		owner, err := a.users.PortOwner(req.Port)
		if err != nil {
			a.logger.Errorf("admin", "check port owner: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if owner != "" && owner != req.Username {
			http.Error(w, fmt.Sprintf("port %d is already assigned to %q", req.Port, owner), http.StatusConflict)
			return
		}
	}

	if err := a.ports.UpdateUserPort(req.Username, req.Port); err != nil {
		if errors.Is(err, userdb.ErrUnknownUser) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		a.logger.Errorf("admin", "update port: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type enabledRequest struct {
	Username string `json:"username"`
	Enabled  bool   `json:"enabled"`
}

func (a *api) handleSetEnabled(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req enabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	if err := a.users.SetEnabled(req.Username, req.Enabled); err != nil {
		if errors.Is(err, userdb.ErrUnknownUser) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		a.logger.Errorf("admin", "set enabled: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Start or stop the port listener without changing the DB port assignment
	users, _ := a.users.List()
	for _, u := range users {
		if u.Username == req.Username && u.Port > 0 {
			if req.Enabled {
				a.ports.StartListener(req.Username, u.Port)
			} else {
				a.ports.StopListener(u.Port)
			}
			break
		}
	}

	w.WriteHeader(http.StatusOK)
}

type dnsRequest struct {
	Username    string `json:"username"`
	DNSServer   string `json:"dns_server"`
	DNSProtocol string `json:"dns_protocol"`
}

func (a *api) handleUpdateDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req dnsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Validate protocol if server is set.
	if req.DNSServer != "" {
		switch req.DNSProtocol {
		case "plain", "tls", "https":
		default:
			http.Error(w, "dns_protocol must be 'plain', 'tls', or 'https'", http.StatusBadRequest)
			return
		}
		req.DNSServer = normalizeDNSServer(req.DNSServer, req.DNSProtocol)
	}

	if err := a.users.UpdateDNS(req.Username, req.DNSServer, req.DNSProtocol); err != nil {
		if errors.Is(err, userdb.ErrUnknownUser) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		a.logger.Errorf("admin", "update dns: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// normalizeDNSServer adds default ports or scheme when omitted.
func normalizeDNSServer(server, protocol string) string {
	switch protocol {
	case "plain", "tls":
		if _, _, err := net.SplitHostPort(server); err != nil {
			port := "53"
			if protocol == "tls" {
				port = "853"
			}
			return net.JoinHostPort(server, port)
		}
	case "https":
		if !strings.HasPrefix(server, "https://") {
			return "https://" + server
		}
	}
	return server
}

type dnsTestRequest struct {
	DNSServer   string `json:"dns_server"`
	DNSProtocol string `json:"dns_protocol"`
}

type dnsTestResponse struct {
	OK        bool     `json:"ok"`
	Addresses []string `json:"addresses,omitempty"`
	Error     string   `json:"error,omitempty"`
}

func (a *api) handleTestDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req dnsTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	switch req.DNSProtocol {
	case "plain", "tls", "https":
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dnsTestResponse{Error: "invalid protocol"})
		return
	}

	req.DNSServer = normalizeDNSServer(req.DNSServer, req.DNSProtocol)

	resolver, err := edns.New(req.DNSProtocol, req.DNSServer)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dnsTestResponse{Error: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	addrs, err := resolver.LookupIPAddr(ctx, "google.com")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dnsTestResponse{Error: err.Error()})
		return
	}

	ips := make([]string, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP.String()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dnsTestResponse{OK: true, Addresses: ips})
}

type downtimeRequest struct {
	Username         string                  `json:"username"`
	DowntimeSchedule userdb.DowntimeSchedule `json:"downtime_schedule"`
}

func (a *api) handleUpdateDowntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req downtimeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Validate schedule (nil/empty clears downtime)
	if len(req.DowntimeSchedule) > 0 {
		if err := userdb.ValidateSchedule(req.DowntimeSchedule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if err := a.users.UpdateDowntime(req.Username, req.DowntimeSchedule); err != nil {
		if errors.Is(err, userdb.ErrUnknownUser) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		a.logger.Errorf("admin", "update downtime: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type overrideRequest struct {
	Username        string `json:"username"`
	DurationMinutes int    `json:"duration_minutes"`
}

func (a *api) handleDowntimeOverride(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req overrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	if req.DurationMinutes <= 0 {
		// Clear override
		if err := a.users.ClearDowntimeOverride(req.Username); err != nil {
			if errors.Is(err, userdb.ErrUnknownUser) {
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			a.logger.Errorf("admin", "clear downtime override: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	} else {
		until := time.Now().Add(time.Duration(req.DurationMinutes) * time.Minute)
		if err := a.users.SetDowntimeOverride(req.Username, until); err != nil {
			if errors.Is(err, userdb.ErrUnknownUser) {
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			a.logger.Errorf("admin", "set downtime override: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Immediately start the user's dedicated port listener so they
		// don't have to wait for the next reconciler tick.
		users, _ := a.users.List()
		for _, u := range users {
			if u.Username == req.Username && u.Port > 0 {
				a.ports.StartListener(req.Username, u.Port)
				break
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (a *api) handleLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Establish the stream immediately. Go doesn't send the response header until
	// the first Write, so a quiet server (e.g. the no-traffic demo build) would
	// otherwise leave the client hanging with no response headers until the first
	// log event — which may never come. Flush an SSE comment (ignored by parsers)
	// so the client sees 200 and an open stream right away.
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ch := a.stats.Subscribe()
	defer a.stats.Unsubscribe(ch)

	// Heartbeat keeps the connection alive through idle periods and intermediary
	// proxies (e.g. Cloudflare) when there is no log traffic at all.
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()

	for {
		select {
		case entry := <-ch:
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
