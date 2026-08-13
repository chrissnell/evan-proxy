package admin

import (
	"net"
	"net/http"
	"strings"
)

// clientIP returns the caller's IP. It only honors X-Forwarded-For when the
// immediate peer (RemoteAddr) is inside one of the trustedProxies networks;
// otherwise a client can spoof the header and evade rate limiting. The XFF
// client is the left-most entry (the original client).
func clientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer != nil && len(trustedProxies) > 0 {
		for _, n := range trustedProxies {
			if n.Contains(peer) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					first := strings.TrimSpace(strings.Split(xff, ",")[0])
					if net.ParseIP(first) != nil {
						return first
					}
				}
				break
			}
		}
	}
	return host
}
