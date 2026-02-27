package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// UserEnabledChecker returns whether a user is enabled.
type UserEnabledChecker interface {
	IsEnabled(username string) bool
}

// StartUserListeners loads port assignments from the DB and starts a
// dedicated HTTP listener for each enabled user.
func (h *Handler) StartUserListeners() error {
	ports, err := h.portDB.ListPorts()
	if err != nil {
		return fmt.Errorf("loading port assignments: %w", err)
	}

	h.portMu.Lock()
	defer h.portMu.Unlock()

	for port, username := range ports {
		if port < h.cfg.UserPortMin || port > h.cfg.UserPortMax {
			h.logger.Infof("userports", "ignoring out-of-range port %d for %q", port, username)
			continue
		}
		if !h.enabledChecker.IsEnabled(username) {
			h.logger.Infof("userports", "skipping disabled user %q (port %d)", username, port)
			continue
		}
		h.portUsers[port] = username
		h.startListenerLocked(port, username)
	}
	return nil
}

// startListenerLocked starts a listener for a single port. Caller must hold portMu.
func (h *Handler) startListenerLocked(port int, username string) {
	portUser := username // capture for closure
	srv := &http.Server{
		Addr:        fmt.Sprintf(":%d", port),
		IdleTimeout: h.cfg.IdleTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), portOwnerKey, portUser)
			h.ServeHTTP(w, r.WithContext(ctx))
		}),
	}

	h.userServers[port] = srv

	go func() {
		h.logger.Infof("userports", "listening on :%d for %q", port, username)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			h.logger.Errorf("userports", "port %d: %v", port, err)
		}
	}()
}

// StopUserListener gracefully shuts down the listener for a single port.
func (h *Handler) StopUserListener(port int) {
	h.portMu.Lock()
	srv, ok := h.userServers[port]
	if ok {
		delete(h.userServers, port)
		delete(h.portUsers, port)
	}
	h.portMu.Unlock()

	if ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		h.logger.Infof("userports", "stopped listener on :%d", port)
	}
}

// StartListener starts a listener for a user on a specific port (without DB changes).
func (h *Handler) StartListener(username string, port int) {
	h.portMu.Lock()
	h.portUsers[port] = username
	h.startListenerLocked(port, username)
	h.portMu.Unlock()
}

// StopListener stops a listener on a specific port (without DB changes).
func (h *Handler) StopListener(port int) {
	h.StopUserListener(port)
}

// UpdateUserPort assigns a port to a user, starting/stopping listeners as needed.
// Pass port=0 to unassign.
func (h *Handler) UpdateUserPort(username string, port int) error {
	// Find and stop any existing listener for this user
	h.portMu.RLock()
	var oldPort int
	for p, u := range h.portUsers {
		if u == username {
			oldPort = p
			break
		}
	}
	h.portMu.RUnlock()

	if oldPort != 0 {
		h.StopUserListener(oldPort)
	}

	// Update DB
	if err := h.portDB.UpdatePort(username, port); err != nil {
		return err
	}

	if port == 0 {
		return nil
	}

	// Start new listener
	h.portMu.Lock()
	h.portUsers[port] = username
	h.startListenerLocked(port, username)
	h.portMu.Unlock()

	return nil
}

// ShutdownUserListeners gracefully stops all per-user listeners.
func (h *Handler) ShutdownUserListeners(ctx context.Context) {
	h.portMu.Lock()
	servers := make(map[int]*http.Server, len(h.userServers))
	for p, s := range h.userServers {
		servers[p] = s
	}
	h.userServers = make(map[int]*http.Server)
	h.portUsers = make(map[int]string)
	h.portMu.Unlock()

	for port, srv := range servers {
		srv.Shutdown(ctx)
		h.logger.Infof("userports", "stopped listener on :%d", port)
	}
}

// UserPortRange returns the configured port range.
func (h *Handler) UserPortRange() (min, max int) {
	return h.cfg.UserPortMin, h.cfg.UserPortMax
}
