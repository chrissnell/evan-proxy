package admin

import (
	"net"
	"net/http"
	"strings"
)

// clientIP returns the caller's IP. It only honors X-Forwarded-For when the
// immediate peer (RemoteAddr) is inside one of the trustedProxies networks;
// otherwise a client can spoof the header and evade rate limiting.
//
// A trusted proxy (ingress/LB) appends the address it observed to the right of
// X-Forwarded-For, so the header reads "<client-supplied…>, <observed peer>".
// The left-most entries are attacker-controlled and must not be trusted. We
// therefore walk right-to-left, skip addresses that are themselves trusted
// proxies, and return the first untrusted address — the real client as seen by
// our edge. Anything an attacker prepends stays to the left and is ignored.
func clientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || len(trustedProxies) == 0 || !ipInAny(peer, trustedProxies) {
		return host
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(parts[i])
		ip := net.ParseIP(ipStr)
		if ip == nil || ipInAny(ip, trustedProxies) {
			continue
		}
		return ipStr
	}
	return host
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
