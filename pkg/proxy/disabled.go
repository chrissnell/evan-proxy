package proxy

import (
	"embed"
	"net"
	"net/http"
)

//go:embed static/disabled.html
var disabledFS embed.FS

func serveDisabled(w http.ResponseWriter, r *http.Request) {
	// For CONNECT, hijack and send a proper proxy 503 with
	// Retry-After so iOS treats this as a temporary condition
	// rather than caching the host as permanently unreachable.
	if r.Method == http.MethodConnect {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		// Send RST instead of FIN by setting SO_LINGER to 0.
		// Clients see "connection reset" — a clear transient failure
		// that TCP stacks handle gracefully with quick retry/fallback.
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		conn.Close()
		return
	}

	data, err := disabledFS.ReadFile("static/disabled.html")
	if err != nil {
		http.Error(w, "proxy is disabled", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write(data)
}
