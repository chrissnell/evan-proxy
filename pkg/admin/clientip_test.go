package admin

import (
	"net"
	"net/http/httptest"
	"testing"
)

func mustCIDR(s string) *net.IPNet { _, n, _ := net.ParseCIDR(s); return n }

func TestClientIP_NoTrustedProxies_UsesRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r, nil); got != "203.0.113.9" {
		t.Fatalf("want 203.0.113.9, got %q", got)
	}
}

func TestClientIP_TrustedProxy_UsesXFF(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8")}
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "10.0.0.5:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.5")
	if got := clientIP(r, trusted); got != "1.2.3.4" {
		t.Fatalf("want 1.2.3.4, got %q", got)
	}
}

func TestClientIP_UntrustedPeer_IgnoresXFF(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8")}
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r, trusted); got != "203.0.113.9" {
		t.Fatalf("want 203.0.113.9, got %q", got)
	}
}

// An attacker who prepends a bogus XFF value cannot control the resolved IP:
// the trusted proxy appends the real observed peer on the right, and we ignore
// anything to the left of it.
func TestClientIP_TrustedProxy_IgnoresSpoofedLeftmost(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8")}
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "10.0.0.5:5555"
	// Attacker sent "6.6.6.6"; the trusted proxy appended the attacker's real IP.
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7")
	if got := clientIP(r, trusted); got != "198.51.100.7" {
		t.Fatalf("want 198.51.100.7 (real client), got %q", got)
	}
}

// Multiple trusted hops: skip trusted addresses right-to-left and return the
// first untrusted one.
func TestClientIP_MultipleTrustedHops(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8"), mustCIDR("172.16.0.0/12")}
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "10.0.0.5:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.4, 172.16.9.9, 10.0.0.6")
	if got := clientIP(r, trusted); got != "203.0.113.4" {
		t.Fatalf("want 203.0.113.4, got %q", got)
	}
}

// IPv6 RemoteAddr must parse and, with no trusted proxies, be returned as-is.
func TestClientIP_IPv6RemoteAddr(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "[2001:db8::1]:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r, nil); got != "2001:db8::1" {
		t.Fatalf("want 2001:db8::1, got %q", got)
	}
}

// If XFF holds only trusted-proxy addresses (no real client entry), fall back
// to the peer rather than returning a proxy IP.
func TestClientIP_AllTrusted_FallsBackToPeer(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR("10.0.0.0/8")}
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "10.0.0.5:5555"
	r.Header.Set("X-Forwarded-For", "10.0.0.6, 10.0.0.5")
	if got := clientIP(r, trusted); got != "10.0.0.5" {
		t.Fatalf("want 10.0.0.5, got %q", got)
	}
}
