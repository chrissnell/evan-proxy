package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"evan-proxy/pkg/acl"
	"evan-proxy/pkg/config"
	edns "evan-proxy/pkg/dns"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/ratelimit"
	"evan-proxy/pkg/stats"
)

// UserChecker validates proxy authentication credentials.
type UserChecker interface {
	Check(proxyAuthHeader string) (string, error)
}

// UserDNSGetter returns per-user DNS configuration.
type UserDNSGetter interface {
	GetDNS(username string) (server, protocol string)
}

// PortLister returns per-user port assignments from the database.
type PortLister interface {
	ListPorts() (map[int]string, error)
	UpdatePort(username string, port int) error
	PortOwner(port int) (string, error)
}

// ErrDNSBlocked is returned when DNS resolves to a loopback or null address.
var ErrDNSBlocked = errors.New("dns blocked")

type ctxKey int

const (
	dnsResolverKey ctxKey = iota
	portOwnerKey
)

// authSession tracks a recently authenticated client IP.
type authSession struct {
	user    string
	expires time.Time
}

type Handler struct {
	users           UserChecker
	dnsGetter       UserDNSGetter
	portDB          PortLister
	enabledChecker  UserEnabledChecker
	acl             acl.ACL
	limiter         *ratelimit.Limiter
	logger          *logging.Logger
	counter         *stats.TrafficCounter
	transport       *http.Transport
	dial            func(ctx context.Context, network, address string) (net.Conn, error)
	cfg             *config.Config
	defaultResolver *edns.Resolver

	// IP-based auth cache: after a client authenticates, allow subsequent
	// requests from the same IP without re-challenging. This handles
	// iOS/macOS which may not retry CONNECT auth for subresource requests.
	authMu       sync.RWMutex
	authSessions map[string]authSession
	authStopCh   chan struct{}

	// Per-user dedicated port listeners
	portMu      sync.RWMutex
	portUsers   map[int]string       // port → username
	userServers map[int]*http.Server // port → running server
}

// loopbackNet covers 127.0.0.0/8 used by DNS-blocking resolvers.
var loopbackNet = net.IPNet{
	IP:   net.IPv4(127, 0, 0, 0),
	Mask: net.CIDRMask(8, 32),
}

// isDNSBlocked returns true if the IP is a null/loopback address typically
// returned by DNS-level ad blockers (0.0.0.0, 127.0.0.0/8).
func isDNSBlocked(ip net.IP) bool {
	return ip.IsLoopback() || ip.Equal(net.IPv4zero) || loopbackNet.Contains(ip)
}

func New(cfg *config.Config, users UserChecker, dnsGetter UserDNSGetter, portDB PortLister, enabled UserEnabledChecker, a acl.ACL, rl *ratelimit.Limiter, lg *logging.Logger, tc *stats.TrafficCounter) *Handler {
	defaultResolver, err := edns.New(cfg.DNSProtocol, cfg.DNSServer)
	if err != nil {
		panic(fmt.Sprintf("dns resolver: %v", err))
	}

	dialer := &net.Dialer{
		Timeout: cfg.ConnectDialTimeout,
	}
	if nr := defaultResolver.NetResolver(); nr != nil {
		dialer.Resolver = nr
	}

	h := &Handler{
		users:           users,
		dnsGetter:       dnsGetter,
		portDB:          portDB,
		enabledChecker:  enabled,
		acl:             a,
		limiter:         rl,
		logger:          lg,
		counter:         tc,
		cfg:             cfg,
		defaultResolver: defaultResolver,
		authSessions:    make(map[string]authSession),
		authStopCh:      make(chan struct{}),
		portUsers:       make(map[int]string),
		userServers:     make(map[int]*http.Server),
	}
	go h.cleanupAuthSessions()

	// Wraps DialContext to detect DNS-blocked addresses before connecting.
	// Reads per-user resolver from context; falls back to the global default.
	dialWithBlockCheck := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return dialer.DialContext(ctx, network, address)
		}

		// Only check hostnames, not bare IPs
		if net.ParseIP(host) == nil {
			resolver := h.resolverFromCtx(ctx)
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("dns: no addresses for %s", host)
			}
			if isDNSBlocked(ips[0].IP) {
				return nil, fmt.Errorf("%w: %s resolved to %s", ErrDNSBlocked, host, ips[0].IP)
			}
			// Dial the resolved IP directly to avoid double resolution
			address = net.JoinHostPort(ips[0].IP.String(), port)
		}

		return dialer.DialContext(ctx, network, address)
	}

	h.transport = &http.Transport{
		DialContext:           dialWithBlockCheck,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.HTTPTimeout,
	}
	h.dial = dialWithBlockCheck

	return h
}

// resolverFromCtx returns the per-user resolver from context, or the global default.
func (h *Handler) resolverFromCtx(ctx context.Context) *edns.Resolver {
	if r, ok := ctx.Value(dnsResolverKey).(*edns.Resolver); ok && r != nil {
		return r
	}
	return h.defaultResolver
}

// ctxWithUserDNS returns a context with the per-user DNS resolver attached, if configured.
func (h *Handler) ctxWithUserDNS(ctx context.Context, username string) context.Context {
	if h.dnsGetter == nil {
		return ctx
	}
	server, protocol := h.dnsGetter.GetDNS(username)
	if server == "" {
		return ctx
	}
	resolver, err := edns.GetOrCreate(protocol, server)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, dnsResolverKey, resolver)
}

const authSessionTTL = 5 * time.Minute

// authCacheKey builds the session cache key scoped to the expected port owner.
func authCacheKey(ip, portUser string) string {
	if portUser == "" {
		return ip
	}
	return ip + ":" + portUser
}

// recordAuthSuccess caches a successful auth for an IP, scoped to port owner.
func (h *Handler) recordAuthSuccess(ip, user string) {
	key := authCacheKey(ip, user)
	h.authMu.Lock()
	h.authSessions[key] = authSession{user: user, expires: time.Now().Add(authSessionTTL)}
	h.authMu.Unlock()
}

// checkAuthSession returns the cached user for an IP+portOwner, or "" if none.
func (h *Handler) checkAuthSession(ip, portUser string) string {
	key := authCacheKey(ip, portUser)
	h.authMu.RLock()
	s, ok := h.authSessions[key]
	h.authMu.RUnlock()
	if ok && time.Now().Before(s.expires) {
		return s.user
	}
	return ""
}

// cleanupAuthSessions periodically removes expired entries from the auth session cache.
func (h *Handler) cleanupAuthSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			h.authMu.Lock()
			for k, s := range h.authSessions {
				if now.After(s.expires) {
					delete(h.authSessions, k)
				}
			}
			h.authMu.Unlock()
		case <-h.authStopCh:
			return
		}
	}
}

// StopAuthCleanup stops the auth session cleanup goroutine.
func (h *Handler) StopAuthCleanup() {
	close(h.authStopCh)
}

// portOwnerFromCtx returns the expected username for the per-user port, or "".
func portOwnerFromCtx(r *http.Request) string {
	if u, ok := r.Context().Value(portOwnerKey).(string); ok {
		return u
	}
	return ""
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleForward(w, r)
	}
}

// clientAddr extracts the client IP without port.
func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
