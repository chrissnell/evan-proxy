package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// Resolver performs DNS lookups using a configured protocol.
type Resolver struct {
	std *net.Resolver // plain and DoT
	doh *dohClient    // DoH
}

// New creates a resolver for the given protocol and server.
// Protocol must be "plain", "tls", or "https".
// Server examples: "1.1.1.1:53", "1.1.1.1:853", "https://1.1.1.1/dns-query".
// Empty server with "plain" protocol uses the system default.
func New(protocol, server string) (*Resolver, error) {
	switch protocol {
	case "plain", "":
		return newPlain(server), nil
	case "tls":
		return newTLS(server)
	case "https":
		return newDoH(server)
	default:
		return nil, fmt.Errorf("unsupported DNS protocol: %q", protocol)
	}
}

// LookupIPAddr resolves a hostname to IP addresses.
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if r.doh != nil {
		return r.doh.lookupIPAddr(ctx, host)
	}
	return r.std.LookupIPAddr(ctx, host)
}

// NetResolver returns the underlying *net.Resolver for use with net.Dialer.
// Returns nil for DoH (which uses HTTP, not the Dial interface).
func (r *Resolver) NetResolver() *net.Resolver {
	return r.std
}

func newPlain(server string) *Resolver {
	if server == "" {
		return &Resolver{std: net.DefaultResolver}
	}
	return &Resolver{
		std: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", server)
			},
		},
	}
}

func newTLS(server string) (*Resolver, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		host = server
		server = net.JoinHostPort(server, "853")
	}
	return &Resolver{
		std: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				conn, err := d.DialContext(ctx, "tcp", server)
				if err != nil {
					return nil, err
				}
				return tls.Client(conn, &tls.Config{ServerName: host}), nil
			},
		},
	}, nil
}

// Global resolver cache keyed by "protocol:server".
var (
	cacheMu sync.RWMutex
	cache   = map[string]*Resolver{}
)

// GetOrCreate returns a cached resolver or creates a new one.
func GetOrCreate(protocol, server string) (*Resolver, error) {
	key := protocol + ":" + server

	cacheMu.RLock()
	if r, ok := cache[key]; ok {
		cacheMu.RUnlock()
		return r, nil
	}
	cacheMu.RUnlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()

	// Double-check after acquiring write lock.
	if r, ok := cache[key]; ok {
		return r, nil
	}

	r, err := New(protocol, server)
	if err != nil {
		return nil, err
	}
	cache[key] = r
	return r, nil
}
