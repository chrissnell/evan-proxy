package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// UserEnabledChecker returns whether a user is enabled.
type UserEnabledChecker interface {
	IsEnabled(username string) bool
}

// StartUserListeners loads port assignments from the DB and starts a
// dedicated HTTP listener for every assigned port. Listeners stay bound for
// the full lifetime of a port assignment regardless of enabled/downtime
// state — disabled and downtime users are blocked at the request layer
// instead (see startListenerLocked and serveBlocked). This keeps the TCP
// port responsive so iOS clients with ProxyPACFallbackAllowed=true never
// see "proxy unreachable" and silently fall back to DIRECT.
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
		h.portUsers[port] = username
		h.startListenerLocked(port, username)
	}
	return nil
}

// StartReconciler starts a background goroutine that periodically ensures
// a dedicated listener is running for every assigned port in the DB and
// that no stale listeners survive for ports that are no longer assigned.
// Enabled/downtime state is handled at the request layer, not by binding
// and unbinding sockets — see serveBlocked.
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

// reconcileListeners ensures a running listener exists for every assigned
// port and tears down listeners whose port is no longer assigned.
// Enabled/downtime state is intentionally NOT consulted here — those are
// enforced at the request layer so the socket keeps accepting (see
// serveBlocked). Binding state is tied purely to port assignment.
func (h *Handler) reconcileListeners() {
	ports, err := h.portDB.ListPorts()
	if err != nil {
		h.logger.Errorf("userports", "reconcile: %v", err)
		return
	}

	// Every assigned, in-range port should have a running listener.
	shouldRun := make(map[int]string)
	for port, username := range ports {
		if port < h.cfg.UserPortMin || port > h.cfg.UserPortMax {
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

	h.portMu.Unlock()

	// Shut down stopped listeners before starting new ones to avoid
	// "address already in use" if a port transitions stop→start.
	for _, s := range toStop {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.srv.Shutdown(ctx)
		cancel()
		h.logger.Infof("userports", "reconcile: stopped listener on :%d", s.port)
	}

	h.portMu.Lock()

	// Start listeners that should be running but aren't
	for port, username := range shouldRun {
		if _, running := h.userServers[port]; !running {
			h.portUsers[port] = username
			h.startListenerLocked(port, username)
		}
	}

	h.portMu.Unlock()
}

// startListenerLocked starts a listener for a single port. Caller must hold portMu.
func (h *Handler) startListenerLocked(port int, username string) {
	portUser := username // capture for closure
	srv := &http.Server{
		Addr:        fmt.Sprintf(":%d", port),
		IdleTimeout: h.cfg.IdleTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always allow the PAC endpoint through, even when the owning
			// user is disabled or in downtime: iOS re-fetches /proxy.pac and
			// treats a failed fetch as "PAC unavailable", which — with
			// ProxyPACFallbackAllowed=true in the mobileconfig — causes a
			// silent fallback to DIRECT. That would defeat the whole point
			// of keeping the port bound to block the user.
			if h.isPACRequest(r) {
				h.servePAC(w, r)
				return
			}
			if !h.enabledChecker.IsEnabled(portUser) ||
				(h.downtimeChecker != nil && h.downtimeChecker.IsInDowntime(portUser)) {
				h.serveBlocked(w, r, portUser)
				return
			}
			ctx := context.WithValue(r.Context(), portOwnerKey, portUser)
			h.ServeHTTP(w, r.WithContext(ctx))
		}),
	}

	h.userServers[port] = srv

	// Demo mode: record the listener for bookkeeping so the admin API and
	// reconciler treat the port as active, but never bind a real socket. Used
	// for App Store validation builds where the full API must work without
	// opening any proxy ports. Not for the shipped release.
	if h.cfg.DemoMode {
		h.logger.Infof("userports", "demo mode: not binding :%d for %q (no real proxy listener)", port, username)
		return
	}

	go func() {
		h.logger.Infof("userports", "listening on :%d for %q", port, username)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			h.logger.Errorf("userports", "port %d: %v", port, err)
			// Remove from maps so the reconciler can retry on the next tick
			h.portMu.Lock()
			if h.userServers[port] == srv {
				delete(h.userServers, port)
				delete(h.portUsers, port)
			}
			h.portMu.Unlock()
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

// serveBlocked handles a request for a user who is disabled or in downtime
// without closing the port. iOS treats a dead-TCP proxy with
// ProxyPACFallbackAllowed=true as "proxy broken" and silently falls back to
// DIRECT; instead we keep the socket responsive and respond in a way iOS
// treats as "proxy worked, upstream is unreachable" — the connection fails
// at the app layer rather than disabling the proxy.
//
// Plain HTTP (non-CONNECT) always returns 403 — a well-formed HTTP error
// is unambiguous. CONNECT shape is controlled by cfg.BlockResponse so we
// can empirically find the response iOS does NOT fall back on.
func (h *Handler) serveBlocked(w http.ResponseWriter, r *http.Request, user string) {
	h.logger.Infof("userports", "blocked %s %s for %q (mode=%s)",
		r.Method, r.Host, user, h.cfg.BlockResponse)

	if r.Method != http.MethodConnect || h.cfg.BlockResponse == "connect-403" {
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	// Accept the tunnel setup so iOS sees a working proxy, then close.
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		return
	}
	switch h.cfg.BlockResponse {
	case "connect-delay-close":
		time.Sleep(50 * time.Millisecond)
	case "connect-rst":
		// Make Close() emit a TCP RST rather than FIN — stronger
		// "upstream crashed" signal that may be less fallback-prone.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
	case "connect-tls-alert":
		// TLS 1.2 fatal alert record carrying access_denied(49). Written
		// on the tunnel immediately after 200 Established so iOS reads
		// it as "destination server rejected my TLS handshake" rather
		// than "proxy misbehaved" — the four other modes all fall back
		// to DIRECT via ProxyPACFallbackAllowed=true because iOS treats
		// any proxy-layer failure as reason to retry direct, but a TLS
		// alert looks like a server-side error at the destination.
		//
		//   0x15                  ContentType: alert
		//   0x03 0x03             ProtocolVersion: TLS 1.2
		//                         (TLS 1.3 handshakes still use 1.2 at
		//                         the record layer during the initial
		//                         flight, so this is accepted either way)
		//   0x00 0x02             Length: 2
		//   0x02 0x31             AlertLevel: fatal, AlertDescription:
		//                         access_denied(49)
		_, _ = conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31})
	}
	conn.Close()
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
