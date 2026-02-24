package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"evan-proxy/pkg/auth"
	edns "evan-proxy/pkg/dns"
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
	auth     *auth.AdminAuth
	sessions *SessionStore
	stats    *stats.Collector
	users    *userdb.DB
	ports    PortManager
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

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Floor response time at 200ms to prevent timing attacks
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed < 200*time.Millisecond {
			time.Sleep(200*time.Millisecond - elapsed)
		}
	}()

	if err := a.auth.Check(req.Username, req.Password); err != nil {
		log.Printf("admin login failed from %s: %v", r.RemoteAddr, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := a.sessions.Create()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
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
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusOK)
}

// requireSession wraps a handler with session authentication.
func (a *api) requireSession(next http.HandlerFunc) http.HandlerFunc {
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
		log.Printf("list users: %v", err)
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
		log.Printf("create user: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Start the per-user port listener
	if err := a.ports.UpdateUserPort(req.Username, port); err != nil {
		log.Printf("start user listener: %v", err)
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
		log.Printf("delete user: %v", err)
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
		log.Printf("change password: %v", err)
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
			log.Printf("check port owner: %v", err)
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
		log.Printf("update port: %v", err)
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
		log.Printf("set enabled: %v", err)
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
		log.Printf("update dns: %v", err)
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

func (a *api) handleLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := a.stats.Subscribe()
	defer a.stats.Unsubscribe(ch)

	for {
		select {
		case entry := <-ch:
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
