package proxy

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
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

	// Authenticate the user
	portUser := portOwnerFromCtx(r)
	hadCredentials := r.Header.Get("Proxy-Authorization") != ""
	user, authErr := h.users.Check(r.Header.Get("Proxy-Authorization"))

	// If credentials were provided but for the wrong user on this port, reject.
	if authErr == nil && portUser != "" && user != portUser {
		authErr = fmt.Errorf("user %q not allowed on this port (owner: %q)", user, portUser)
		user = ""
	}

	// Fall back to IP-based auth session cache (iOS/macOS compatibility).
	if authErr != nil && !hadCredentials {
		if sessionUser := h.checkAuthSession(clientIP, portUser); sessionUser != "" {
			user = sessionUser
			authErr = nil
		}
	}

	if authErr != nil {
		if hadCredentials {
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

	// Cache successful auth for this IP+user
	h.recordAuthSuccess(clientIP, user)

	// Downtime check — user is authenticated but blocked during scheduled downtime
	if h.downtimeChecker != nil && h.downtimeChecker.IsInDowntime(user) {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusForbidden)
		h.logger.Log(logging.Entry{
			Timestamp: start, ClientIP: clientIP, Method: r.Method,
			Host: host, URI: r.RequestURI, User: user, Status: 403,
			Error: "downtime", DurationMS: time.Since(start).Milliseconds(),
		})
		return
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
			Error: "acl denied", DurationMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// Strip hop-by-hop headers before forwarding
	outReq := r.Clone(ctx)
	var stripped []string
	for _, hdr := range hopByHopHeaders {
		if outReq.Header.Get(hdr) != "" {
			stripped = append(stripped, hdr)
		}
		outReq.Header.Del(hdr)
	}
	// Don't add X-Forwarded-For (privacy)
	if outReq.Header.Get("X-Forwarded-For") != "" {
		stripped = append(stripped, "X-Forwarded-For")
	}
	outReq.Header.Del("X-Forwarded-For")

	// Convert to a standard request (remove proxy absolute URI)
	outReq.RequestURI = ""

	if h.cfg.LogHeaders {
		h.logForwardHeaders(clientIP, user, r, outReq, stripped)
	}

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		status, event := classifyDialError(err)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(status)
		h.logger.Log(logging.Entry{
			Timestamp: start, Event: event, ClientIP: clientIP, Method: r.Method,
			Host: host, URI: r.RequestURI, User: user, Status: status,
			Error: err.Error(), DurationMS: time.Since(start).Milliseconds(),
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

// sensitiveHeaders are redacted in header dumps to avoid logging credentials.
var sensitiveHeaders = map[string]bool{
	"Proxy-Authorization": true,
	"Authorization":       true,
	"Cookie":              true,
	"Set-Cookie":          true,
}

// logForwardHeaders emits a diagnostic dump of the inbound request headers, the
// hop-by-hop headers stripped by the proxy, and the exact headers forwarded
// upstream. It exists to answer "is the proxy modifying requests?" — enable it
// with LOG_HEADERS=true. Sensitive values are redacted. This only covers the
// plain-HTTP forward path; CONNECT (HTTPS) traffic is an opaque TCP tunnel and
// its request/response headers are encrypted end-to-end and never touched.
func (h *Handler) logForwardHeaders(clientIP, user string, in, out *http.Request, stripped []string) {
	strippedStr := "(none)"
	if len(stripped) > 0 {
		strippedStr = strings.Join(stripped, ", ")
	}
	h.logger.Infof("headers", "forward %s %s user=%s client=%s\n  inbound:  %s\n  stripped: %s\n  outbound: %s",
		in.Method, in.URL, user, clientIP,
		formatHeaders(in.Header), strippedStr, formatHeaders(out.Header))
}

// formatHeaders renders headers as a stable, single-line "k=v; k=v" string with
// sensitive values redacted.
func formatHeaders(hdr http.Header) string {
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := strings.Join(hdr.Values(k), ",")
		if sensitiveHeaders[http.CanonicalHeaderKey(k)] {
			v = "<redacted>"
		}
		parts = append(parts, k+"="+v)
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, "; ")
}

func isHopByHop(header string) bool {
	for _, h := range hopByHopHeaders {
		if http.CanonicalHeaderKey(header) == http.CanonicalHeaderKey(h) {
			return true
		}
	}
	return false
}
