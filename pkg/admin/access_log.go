package admin

import (
	"net/http"
	"strings"

	"evan-proxy/pkg/logging"
)

// LogRequests wraps h with a lightweight access log: method, path, response
// status, and whether the request carried a bearer token or a session cookie
// (never the value itself), plus the User-Agent. It exists to diagnose client
// behaviour on the demo build — it is noisy and records request paths, so it is
// wired in only when demo mode is on (see cmd/evan-proxy/main.go).
func LogRequests(lg *logging.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := "none"
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			auth = "bearer"
		} else if _, err := r.Cookie(sessionCookie); err == nil {
			auth = "cookie"
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		lg.Infof("access", "%s %s -> %d auth=%s ua=%q", r.Method, r.URL.Path, sw.status, auth, r.Header.Get("User-Agent"))
	})
}

// statusWriter records the response status while preserving the streaming
// (Flusher) capability the SSE log endpoint depends on.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
