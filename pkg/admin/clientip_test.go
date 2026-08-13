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
