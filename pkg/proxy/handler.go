package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"evan-proxy/pkg/acl"
	"evan-proxy/pkg/admin"
	"evan-proxy/pkg/config"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/ratelimit"
	"evan-proxy/pkg/stats"
)

// UserChecker validates proxy authentication credentials.
type UserChecker interface {
	Check(proxyAuthHeader string) (string, error)
}

// ErrDNSBlocked is returned when DNS resolves to a loopback or null address.
var ErrDNSBlocked = errors.New("dns blocked")

type Handler struct {
	users     UserChecker
	acl       acl.ACL
	limiter   *ratelimit.Limiter
	logger    *logging.Logger
	counter   *stats.TrafficCounter
	transport *http.Transport
	dial      func(ctx context.Context, network, address string) (net.Conn, error)
	state     *admin.ProxyState
	cfg       *config.Config
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

func New(cfg *config.Config, users UserChecker, a acl.ACL, rl *ratelimit.Limiter, lg *logging.Logger, tc *stats.TrafficCounter, state *admin.ProxyState) *Handler {
	dialer := &net.Dialer{
		Timeout: cfg.ConnectDialTimeout,
	}

	var resolver *net.Resolver
	if cfg.DNSServer != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", cfg.DNSServer)
			},
		}
		dialer.Resolver = resolver
	} else {
		resolver = net.DefaultResolver
	}

	// Wraps DialContext to detect DNS-blocked addresses before connecting.
	dialWithBlockCheck := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return dialer.DialContext(ctx, network, address)
		}

		// Only check hostnames, not bare IPs
		if net.ParseIP(host) == nil {
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) > 0 && isDNSBlocked(ips[0].IP) {
				return nil, fmt.Errorf("%w: %s resolved to %s", ErrDNSBlocked, host, ips[0].IP)
			}
			// Dial the resolved IP directly to avoid double resolution
			address = net.JoinHostPort(ips[0].IP.String(), port)
		}

		return dialer.DialContext(ctx, network, address)
	}

	transport := &http.Transport{
		DialContext:           dialWithBlockCheck,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.HTTPTimeout,
	}

	return &Handler{
		users:     users,
		acl:       a,
		limiter:   rl,
		logger:    lg,
		counter:   tc,
		transport: transport,
		dial:      dialWithBlockCheck,
		state:     state,
		cfg:       cfg,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.state.IsEnabled() {
		serveDisabled(w, r)
		return
	}

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
