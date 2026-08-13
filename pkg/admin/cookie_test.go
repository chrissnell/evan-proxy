package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionCookieFor_SecureFlag(t *testing.T) {
	c := sessionCookieFor("tok", true)
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected secure httponly strict cookie, got %+v", c)
	}
	if c.Name != sessionCookie || c.Value != "tok" {
		t.Fatalf("unexpected cookie identity: %+v", c)
	}
	if c.MaxAge != 86400 {
		t.Fatalf("expected MaxAge 86400, got %d", c.MaxAge)
	}
}

func TestSessionCookieFor_InsecureFlag(t *testing.T) {
	c := sessionCookieFor("tok", false)
	if c.Secure {
		t.Fatalf("expected Secure=false when secure=false, got %+v", c)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected httponly strict cookie, got %+v", c)
	}
}

func TestClearedSessionCookie(t *testing.T) {
	c := clearedSessionCookie(true)
	if c.MaxAge != -1 || c.Value != "" {
		t.Fatalf("expected cleared cookie (MaxAge=-1, empty value), got %+v", c)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected secure httponly strict cleared cookie, got %+v", c)
	}
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), true)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Errorf("Strict-Transport-Security = %q, want HSTS header", got)
	}
}

func TestSecurityHeaders_NoHSTSWhenDisabled(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), false)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("Strict-Transport-Security = %q, want empty when hsts disabled", got)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}
