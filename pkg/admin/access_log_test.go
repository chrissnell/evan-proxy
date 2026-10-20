package admin

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"evan-proxy/pkg/logging"
)

func TestLogRequests(t *testing.T) {
	cases := []struct {
		name       string
		authHeader string
		cookie     *http.Cookie
		wantAuth   string
		wantStatus int
	}{
		{
			name:       "bearer token",
			authHeader: "Bearer abc123",
			wantAuth:   "bearer",
			wantStatus: 200,
		},
		{
			name:       "session cookie",
			cookie:     &http.Cookie{Name: sessionCookie, Value: "sess-token"},
			wantAuth:   "cookie",
			wantStatus: 403,
		},
		{
			name:       "no auth",
			wantAuth:   "none",
			wantStatus: 401,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			lg := logging.New(logging.NewConsoleBackend(&buf, "human"))

			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.wantStatus)
				io.WriteString(w, "ok")
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.Header.Set("User-Agent", "test-agent/1.0")
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}

			LogRequests(lg, inner).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if rec.Body.String() != "ok" {
				t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
			}

			log := buf.String()
			if !strings.Contains(log, "auth="+tc.wantAuth) {
				t.Errorf("log missing auth=%s: %s", tc.wantAuth, log)
			}
			if !strings.Contains(log, "GET /api/test") {
				t.Errorf("log missing method+path: %s", log)
			}
			if !strings.Contains(log, "-> "+strconv.Itoa(tc.wantStatus)) {
				t.Errorf("log missing status %d: %s", tc.wantStatus, log)
			}
			if !strings.Contains(log, `"test-agent/1.0"`) {
				t.Errorf("log missing user-agent: %s", log)
			}
		})
	}
}

func TestLogRequestsDefaultsToOK(t *testing.T) {
	var buf bytes.Buffer
	lg := logging.New(logging.NewConsoleBackend(&buf, "human"))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/data", nil)

	LogRequests(lg, inner).ServeHTTP(rec, req)

	if !strings.Contains(buf.String(), "-> 200") {
		t.Errorf("expected default status 200 in log: %s", buf.String())
	}
}
