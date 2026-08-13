package admin

import "net/http"

// sessionCookieFor builds the session cookie. Secure is toggled by the caller
// so plain-HTTP local deployments still work while TLS-fronted ones get the
// Secure flag set.
func sessionCookieFor(token string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	}
}

// clearedSessionCookie expires the session cookie on logout, mirroring the
// attributes of the cookie it replaces so browsers actually overwrite it.
func clearedSessionCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
}

// securityHeaders sets baseline response headers on every admin response. HSTS
// is only emitted when TLS is in front, otherwise a browser reaching the admin
// over plain HTTP would be locked out.
func securityHeaders(next http.Handler, hsts bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if hsts {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
