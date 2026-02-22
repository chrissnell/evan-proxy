package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

type api struct {
	auth     *auth.AdminAuth
	state    *ProxyState
	sessions *SessionStore
	stats    *stats.Collector
	users    *userdb.DB
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type statusResponse struct {
	Enabled bool `json:"enabled"`
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
		MaxAge:   3600,
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

func (a *api) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResponse{Enabled: a.state.IsEnabled()})
}

func (a *api) handleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	newState := a.state.Toggle()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResponse{Enabled: newState})
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

func (a *api) handleListUsers(w http.ResponseWriter, r *http.Request) {
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

	if err := a.users.Add(req.Username, req.Password); err != nil {
		if errors.Is(err, userdb.ErrUserExists) {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}
		log.Printf("create user: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (a *api) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
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
