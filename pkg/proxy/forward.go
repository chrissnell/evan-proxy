package proxy

import (
	"errors"
	"io"
	"net/http"
	"time"

	"evan-proxy/pkg/logging"
)

// Hop-by-hop headers that must not be forwarded.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	"Via",
}

// handleForward handles non-CONNECT HTTP requests (plain HTTP forwarding).
func (h *Handler) handleForward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := clientAddr(r)
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	// Rate limit check
	if !h.limiter.Allow(clientIP) {
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusProxyAuthRequired)
		h.logger.Log(logging.Entry{
			Timestamp: start, ClientIP: clientIP, Method: r.Method,
			Host: host, URI: r.RequestURI, Status: 407,
			Error:      "rate limited",
			DurationMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// Per-user port: user is already identified by the listening port.
	user := userFromCtx(r.Context())

	// If not pre-identified, require credentials.
	if user == "" {
		var authErr error
		user, authErr = h.users.Check(r.Header.Get("Proxy-Authorization"))
		if authErr != nil {
			if r.Header.Get("Proxy-Authorization") != "" {
				h.limiter.RecordFailure(clientIP)
			}
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
			w.Header().Set("Proxy-Connection", "keep-alive")
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusProxyAuthRequired)
			h.logger.Log(logging.Entry{
				Timestamp: start, ClientIP: clientIP, Method: r.Method,
				Host: host, URI: r.RequestURI, Status: 407,
				Error:      authErr.Error(),
				DurationMS: time.Since(start).Milliseconds(),
			})
			return
		}
	}

	// Attach per-user DNS resolver to context
	ctx := h.ctxWithUserDNS(r.Context(), user)

	// ACL check
	if !h.acl.Allow(host) {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusForbidden)
		h.logger.Log(logging.Entry{
			Timestamp: start, ClientIP: clientIP, Method: r.Method,
			Host: host, URI: r.RequestURI, User: user, Status: 403,
			DurationMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// Strip hop-by-hop headers before forwarding
	outReq := r.Clone(ctx)
	for _, h := range hopByHopHeaders {
		outReq.Header.Del(h)
	}
	// Don't add X-Forwarded-For (privacy)
	outReq.Header.Del("X-Forwarded-For")

	// Convert to a standard request (remove proxy absolute URI)
	outReq.RequestURI = ""

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		status := http.StatusBadGateway
		event := ""
		if errors.Is(err, ErrDNSBlocked) {
			status = 523
			event = "dns-block"
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(status)
		h.logger.Log(logging.Entry{
			Timestamp: start, Event: event, ClientIP: clientIP, Method: r.Method,
			Host: host, URI: r.RequestURI, User: user, Status: status,
			DurationMS: time.Since(start).Milliseconds(),
		})
		return
	}
	defer resp.Body.Close()

	// Copy response headers, stripping hop-by-hop
	for key, vals := range resp.Header {
		if isHopByHop(key) {
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	cw := h.counter.NewWriter(w, false)
	io.Copy(cw, resp.Body)
	cw.Close()

	h.logger.Log(logging.Entry{
		Timestamp:    start,
		ClientIP:     clientIP,
		Method:       r.Method,
		Host:         host,
		URI:          r.RequestURI,
		User:         user,
		Status:       resp.StatusCode,
		DurationMS:   time.Since(start).Milliseconds(),
		BytesWritten: cw.Total(),
	})
}

func isHopByHop(header string) bool {
	for _, h := range hopByHopHeaders {
		if http.CanonicalHeaderKey(header) == http.CanonicalHeaderKey(h) {
			return true
		}
	}
	return false
}
