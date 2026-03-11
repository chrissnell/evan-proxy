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
// dedicated HTTP listener for each enabled, non-downtime user.
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
		if h.downtimeChecker != nil && h.downtimeChecker.IsInDowntime(username) {
			h.logger.Infof("userports", "skipping downtime user %q (port %d)", username, port)
			continue
		}
		h.portUsers[port] = username
		h.startListenerLocked(port, username)
	}
	return nil
}

// StartReconciler starts a background goroutine that periodically checks
// downtime and enabled status, stopping/starting dedicated port listeners
// as needed. This ensures listeners are stopped during downtime windows
// and restarted when they end.
func (h *Handler) StartReconciler(interval time.Duration) {
	h.reconcileStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.reconcileListeners()
			case <-h.reconcileStop:
				return
			}
		}
	}()
}

// StopReconciler stops the background reconciler goroutine.
func (h *Handler) StopReconciler() {
	if h.reconcileStop != nil {
		close(h.reconcileStop)
	}
}

// reconcileListeners ensures dedicated port listeners match current
// enabled + downtime status. Stops listeners for disabled/downtime users
// and starts them for users who should be active.
func (h *Handler) reconcileListeners() {
	ports, err := h.portDB.ListPorts()
	if err != nil {
		h.logger.Errorf("userports", "reconcile: %v", err)
		return
	}

	// Determine which ports should have running listeners
	shouldRun := make(map[int]string)
	for port, username := range ports {
		if port < h.cfg.UserPortMin || port > h.cfg.UserPortMax {
			continue
		}
		if !h.enabledChecker.IsEnabled(username) {
			continue
		}
		if h.downtimeChecker != nil && h.downtimeChecker.IsInDowntime(username) {
			continue
		}
		shouldRun[port] = username
	}

	h.portMu.Lock()

	// Collect listeners to stop (running but shouldn't be)
	var toStop []struct {
		port int
		srv  *http.Server
	}
	for port, srv := range h.userServers {
		if _, ok := shouldRun[port]; !ok {
			toStop = append(toStop, struct {
				port int
				srv  *http.Server
			}{port, srv})
			delete(h.userServers, port)
			delete(h.portUsers, port)
		}
	}

	// Start listeners that should be running but aren't
	for port, username := range shouldRun {
		if _, running := h.userServers[port]; !running {
			h.portUsers[port] = username
			h.startListenerLocked(port, username)
		}
	}

	h.portMu.Unlock()

	// Shut down stopped listeners outside the lock
	for _, s := range toStop {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.srv.Shutdown(ctx)
		cancel()
		h.logger.Infof("userports", "reconcile: stopped listener on :%d", s.port)
	}
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
