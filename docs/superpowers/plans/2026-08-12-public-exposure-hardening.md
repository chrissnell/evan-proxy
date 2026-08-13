# Public Exposure Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the evan-proxy admin API/UI safe to expose on the public internet so the iOS app works remotely, via login brute-force protection, opt-in debug endpoints, a hardened metrics surface, real TLS, and QR-based per-device token authentication.

**Architecture:** Six independently-shippable phases. Phases 1–4 close the concrete holes found in the GRA-417 audit (no login rate limit, unauthenticated pprof, PII on `/metrics`, plaintext admin transport). Phases 5–6 replace the "phone stores the admin password" model with revocable per-device bearer tokens provisioned by scanning a QR code. Each phase maps to one Multica sub-issue and leaves the tree green.

**Tech Stack:** Go 1.x (`net/http`, `modernc.org/sqlite`, `golang.org/x/crypto`), Prometheus client, Helm/Kubernetes, Swift (SwiftUI + swift-openapi-generator, AVFoundation for QR scanning).

**Conventions to follow (from the existing codebase):**
- Config is env-driven in `pkg/config/config.go` via `envOr`/`envInt`/`envBool`/`envDuration`, validated in `validate()`.
- Admin HTTP handlers live in `pkg/admin/api.go`, routes wired in `pkg/admin/server.go`, tests in `pkg/admin/*_test.go` using the `setupAPI(t)` helper.
- `userdb.DB` owns SQLite; new tables are created in `Open()` and column adds go through `migrate()`. Secrets are stored **hashed** (see `hashPassword`/argon2id), never plaintext.
- Table-driven `httptest` handler tests; assert on status codes.
- Helm values in `helm/evan-proxy/values.yaml`, env wired in `templates/deployment.yaml` + `templates/configmap.yaml`.

---

## Phase / Sub-issue map

| Phase | Sub-issue | Deliverable | Depends on |
|-------|-----------|-------------|------------|
| 1 | Login brute-force protection | Rate-limited `/api/login` with trusted-proxy client IP | — |
| 2 | Opt-in debug endpoints | `/debug/pprof` off by default, own loopback listener | — |
| 3 | Metrics hardening | Separate internal metrics listener, drop user-label PII | — |
| 4 | TLS + secure cookie | Helm ingress TLS, `Secure` cookie, HSTS/redirect, optional autocert | — |
| 5 | Device token model (server) | Token store, QR enrollment + pairing endpoints, bearer auth, devices UI | 1, 4 |
| 6 | iOS QR pairing | Scan-to-pair flow, bearer auth, drop stored password | 5 |

Phases 1–4 are parallelizable. 5 depends on 1 (shares the login-limiter wiring) and 4 (bearer tokens require TLS). 6 depends on 5.

---

## Phase 1 — Login brute-force protection

**Files:**
- Modify: `pkg/config/config.go` (add trusted-proxy + admin-login limiter settings)
- Create: `pkg/admin/clientip.go` (trusted-proxy-aware client IP extraction)
- Create: `pkg/admin/clientip_test.go`
- Modify: `pkg/admin/api.go` (wire limiter into `handleLogin`, fix timing floor)
- Modify: `pkg/admin/server.go` (construct + hold the login limiter)
- Modify: `cmd/evan-proxy/main.go` (pass config through to admin server)
- Modify: `pkg/admin/api_test.go` (limiter field in `setupAPI`)
- Modify: `helm/evan-proxy/templates/configmap.yaml`, `values.yaml`, `README.md`

- [ ] **Step 1: Write the failing client-IP test**

Create `pkg/admin/clientip_test.go`:

```go
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
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./pkg/admin/ -run TestClientIP -v`
Expected: FAIL — `undefined: clientIP`.

- [ ] **Step 3: Implement `clientIP`**

Create `pkg/admin/clientip.go`:

```go
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
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test ./pkg/admin/ -run TestClientIP -v`
Expected: PASS (all three).

- [ ] **Step 5: Commit**

```bash
git add pkg/admin/clientip.go pkg/admin/clientip_test.go
git commit -m "add trusted-proxy-aware client IP extraction for admin"
```

- [ ] **Step 6: Add config for trusted proxies + admin login limiter**

In `pkg/config/config.go`, add to the `Config` struct:

```go
	// Admin login brute-force protection
	AdminLoginRateLimit int           // per-IP failures allowed within the window
	AdminLoginWindow    time.Duration // sliding window for per-IP failures
	AdminLoginGlobalMax int           // global failure ceiling across all IPs in the window (0 = disabled)
	TrustedProxyCIDRs   []string      // CIDRs whose X-Forwarded-For is trusted; empty = trust none
```

In `Load()` add:

```go
		AdminLoginRateLimit: envInt("ADMIN_LOGIN_RATE_LIMIT", 5),
		AdminLoginWindow:    envDuration("ADMIN_LOGIN_WINDOW", 15*time.Minute),
		AdminLoginGlobalMax: envInt("ADMIN_LOGIN_GLOBAL_MAX", 100),
		TrustedProxyCIDRs:   envCSV("TRUSTED_PROXY_CIDRS", nil),
```

In `validate()` add (near the other checks):

```go
	for _, c := range c.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("TRUSTED_PROXY_CIDRS entry %q is not a valid CIDR: %w", c, err)
		}
	}
```

Add `"net"` to the imports. Note `envCSV` already returns the fallback when unset — passing `nil` yields `nil`, which means "trust nothing."

- [ ] **Step 7: Add a config test and run it**

In `pkg/config/config_test.go` add:

```go
func TestLoad_InvalidTrustedProxyCIDR(t *testing.T) {
	t.Setenv("ADMIN_USER", "admin")
	t.Setenv("ADMIN_PASSWORD", "$2y$10$abc")
	t.Setenv("TRUSTED_PROXY_CIDRS", "not-a-cidr")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
```

Run: `go test ./pkg/config/ -run TestLoad_InvalidTrustedProxyCIDR -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/config/config.go pkg/config/config_test.go
git commit -m "add admin login rate-limit and trusted-proxy config"
```

- [ ] **Step 9: Write the failing login rate-limit test**

Add to `pkg/admin/api_test.go`. First extend `setupAPI` to build a limiter and parse trusted proxies (add these fields to the returned `&api{...}`), then:

```go
func TestHandleLogin_RateLimitsAfterFailures(t *testing.T) {
	a := setupAPI(t) // configured with limit=3, window=1m in setup
	body := `{"username":"admin","password":"wrong"}`
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
		req.RemoteAddr = "203.0.113.7:1111"
		w := httptest.NewRecorder()
		a.handleLogin(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i, w.Code)
		}
	}
	// 4th attempt (even with correct password) is blocked by the limiter
	req := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"admin","password":"correct-horse"}`))
	req.RemoteAddr = "203.0.113.7:1111"
	w := httptest.NewRecorder()
	a.handleLogin(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after limit, got %d", w.Code)
	}
}
```

Update `setupAPI` to include:

```go
	auth:           auth.NewAdminAuth("admin", mustBcrypt(t, "correct-horse")),
	loginLimiter:   ratelimit.New(3, time.Minute),
	trustedProxies: nil,
```

with a `mustBcrypt` helper:

```go
func mustBcrypt(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
	if err != nil { t.Fatal(err) }
	return string(h)
}
```

Import `"golang.org/x/crypto/bcrypt"`, `"evan-proxy/pkg/auth"`, `"evan-proxy/pkg/ratelimit"`.

- [ ] **Step 10: Run it and confirm it fails**

Run: `go test ./pkg/admin/ -run TestHandleLogin_RateLimits -v`
Expected: FAIL — `a.loginLimiter`/`a.trustedProxies` undefined.

- [ ] **Step 11: Add fields to `api` and wire the limiter into `handleLogin`**

In `pkg/admin/api.go`, add to the `api` struct:

```go
	loginLimiter   *ratelimit.Limiter
	trustedProxies []*net.IPNet
	globalFails    *globalCounter // shared global failure ceiling
```

Replace the body of `handleLogin` so the limiter gates the attempt and only failures are recorded. Remove the broken deferred 200ms floor (it ran after the response was written) — the limiter is the real defense:

```go
func (a *api) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r, a.trustedProxies)
	if !a.loginLimiter.Allow(ip) || !a.globalFails.allow() {
		w.Header().Set("Retry-After", "900")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := a.auth.Check(req.Username, req.Password); err != nil {
		a.loginLimiter.RecordFailure(ip)
		a.globalFails.record()
		a.logger.Errorf("admin", "login failed from %s: %v", ip, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := a.sessions.Create()
	http.SetCookie(w, sessionCookieFor(token, a.secureCookies)) // secureCookies added in Phase 4; use `false` literal until then
	w.WriteHeader(http.StatusOK)
}
```

Add `"io"` and `"net"` to imports. Add a tiny global counter in `pkg/admin/api.go` (or a new `pkg/admin/globalcounter.go`):

```go
type globalCounter struct {
	mu     sync.Mutex
	times  []time.Time
	max    int
	window time.Duration
}

func newGlobalCounter(max int, window time.Duration) *globalCounter {
	return &globalCounter{max: max, window: window}
}
func (g *globalCounter) allow() bool {
	if g.max <= 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := time.Now().Add(-g.window)
	active := g.times[:0]
	for _, t := range g.times {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}
	g.times = active
	return len(active) < g.max
}
func (g *globalCounter) record() {
	if g.max <= 0 {
		return
	}
	g.mu.Lock()
	g.times = append(g.times, time.Now())
	g.mu.Unlock()
}
```

Note: until Phase 4 lands, keep the existing `http.SetCookie(...)` block literally and add `sessionCookieFor`/`secureCookies` in Phase 4. If executing phases in order, use the current inline cookie here and refactor in Phase 4 Step 4.

- [ ] **Step 12: Run the test and confirm it passes**

Run: `go test ./pkg/admin/ -run TestHandleLogin -v`
Expected: PASS.

- [ ] **Step 13: Construct the limiter in `NewServer` and thread config through**

In `pkg/admin/server.go`, change `NewServer` to accept the needed config (or a small `Options` struct) and build:

```go
	a := &api{
		auth:           adminAuth,
		sessions:       sessions,
		stats:          collector,
		users:          users,
		ports:          ports,
		logger:         lg,
		loginLimiter:   ratelimit.New(opts.LoginRateLimit, opts.LoginWindow),
		trustedProxies: opts.TrustedProxies,
		globalFails:    newGlobalCounter(opts.LoginGlobalMax, opts.LoginWindow),
	}
```

Parse `opts.TrustedProxies` from `cfg.TrustedProxyCIDRs` in `cmd/evan-proxy/main.go` (reuse `net.ParseCIDR`) and pass through. Update the `NewServer(...)` call site in `main.go` accordingly.

- [ ] **Step 14: Build and run the full admin + config suites**

Run: `go build ./... && go test ./pkg/admin/ ./pkg/config/ ./cmd/... -v`
Expected: PASS, build clean.

- [ ] **Step 15: Surface the new env vars in Helm + README**

Add to `helm/evan-proxy/values.yaml` under `admin:`:

```yaml
  loginRateLimit: 5
  loginWindow: "15m"
  loginGlobalMax: 100
  # CIDRs whose X-Forwarded-For header is trusted (your ingress/LB). Empty = trust none.
  trustedProxyCIDRs: []
```

Wire them in `templates/configmap.yaml` as `ADMIN_LOGIN_RATE_LIMIT`, `ADMIN_LOGIN_WINDOW`, `ADMIN_LOGIN_GLOBAL_MAX`, and `TRUSTED_PROXY_CIDRS` (join the list with `,`). Document all four in the README config table.

- [ ] **Step 16: Commit**

```bash
git add pkg/admin cmd/evan-proxy/main.go helm README.md
git commit -m "rate-limit admin login by client IP with global ceiling"
```

---

## Phase 2 — Opt-in debug endpoints

**Files:**
- Modify: `pkg/config/config.go` (add `PProfEnabled`, `PProfListen`)
- Modify: `pkg/admin/server.go` (stop registering pprof on the public mux)
- Modify: `cmd/evan-proxy/main.go` (start a separate loopback pprof listener when enabled)
- Modify: `pkg/admin/server_test.go` (assert pprof is 404 on the admin mux)
- Modify: `helm/evan-proxy/values.yaml`, `templates/configmap.yaml`, `README.md`

- [ ] **Step 1: Write the failing test — pprof is not on the admin mux**

In `pkg/admin/server_test.go`:

```go
func TestServer_PprofNotExposed(t *testing.T) {
	srv := newTestServer(t) // helper that builds a Server via NewServer
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	// authenticate the request the same way other page tests do, or assert 404/redirect
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("pprof must not be served on admin mux; got %d", w.Code)
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./pkg/admin/ -run TestServer_PprofNotExposed -v`
Expected: FAIL — pprof currently returns 200/handler output.

- [ ] **Step 3: Remove pprof registration from `server.go`**

Delete these lines from `NewServer` in `pkg/admin/server.go` and the `net/http/pprof` import:

```go
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test ./pkg/admin/ -run TestServer_PprofNotExposed -v`
Expected: PASS.

- [ ] **Step 5: Add config**

In `pkg/config/config.go` add fields and defaults:

```go
	PProfEnabled bool
	PProfListen  string
```
```go
		PProfEnabled: envBool("PPROF_ENABLED", false),
		PProfListen:  envOr("PPROF_LISTEN", "127.0.0.1:6060"),
```

- [ ] **Step 6: Start a separate pprof listener in `main.go` when enabled**

In `cmd/evan-proxy/main.go`, after the admin listener goroutine:

```go
	if cfg.PProfEnabled {
		pmux := http.NewServeMux()
		pmux.HandleFunc("/debug/pprof/", pprof.Index)
		pmux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pmux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pmux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pmux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		go func() {
			logger.Infof("pprof", "listening on %s", cfg.PProfListen)
			if err := http.ListenAndServe(cfg.PProfListen, pmux); err != nil {
				logger.Errorf("pprof", "%v", err)
			}
		}()
	}
```

Import `"net/http/pprof"` in `main.go`. Default `127.0.0.1:6060` is loopback-only, reachable via `kubectl port-forward`, never the public admin port.

- [ ] **Step 7: Build + test**

Run: `go build ./... && go test ./pkg/admin/ ./pkg/config/ -v`
Expected: PASS.

- [ ] **Step 8: Helm + README**

Add `debug: { pprofEnabled: false, pprofListen: "127.0.0.1:6060" }` to `values.yaml`, wire `PPROF_ENABLED`/`PPROF_LISTEN` in `configmap.yaml`, document in README (note: enabling exposes profiling only on the loopback listener, not the admin port).

- [ ] **Step 9: Commit**

```bash
git add pkg/config pkg/admin cmd/evan-proxy/main.go helm README.md
git commit -m "make pprof opt-in on a separate loopback listener"
```

---

## Phase 3 — Metrics hardening

**Files:**
- Modify: `pkg/metrics/metrics.go` (make the per-user label opt-in)
- Modify: `pkg/config/config.go` (`MetricsListen`, `MetricsUserLabel`)
- Modify: `pkg/admin/server.go` (only mount `/metrics` on admin mux when no separate listener)
- Modify: `cmd/evan-proxy/main.go` (separate internal metrics listener)
- Modify: `pkg/metrics/metrics_test.go`
- Modify: `helm/evan-proxy/values.yaml`, `templates/*` (drop `prometheus.io/*` scrape of the public port; add internal metrics port/service), `README.md`

- [ ] **Step 1: Write the failing test — user label omitted by default**

In `pkg/metrics/metrics_test.go`:

```go
func TestObserve_NoUserLabelByDefault(t *testing.T) {
	m := New(Options{UserLabel: false})
	m.Observe(logging.Entry{Event: "request", Method: "GET", Status: 200, User: "alice"})
	// gather registered metrics and assert no series carries a "user" label == "alice"
	got := gatherLabelValues(t, "evanproxy_requests_total", "user")
	for _, v := range got {
		if v == "alice" {
			t.Fatal("user label must not be emitted when UserLabel is false")
		}
	}
}
```

(`gatherLabelValues` uses `prometheus.DefaultGatherer.Gather()` / a custom registry — introduce a registry field on `Metrics` so tests don't collide with the global default registry.)

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./pkg/metrics/ -run TestObserve_NoUserLabel -v`
Expected: FAIL — `New` takes no `Options`; label always emitted.

- [ ] **Step 3: Make the user label opt-in**

Change `New()` to `New(opts Options)` where `Options{ UserLabel bool }`. When `UserLabel` is false, register `requests` with labels `{"method","status_code"}` (no `user`) and drop the user value in `Observe`. Use a private `*prometheus.Registry` instead of `MustRegister` on the global default so metrics can't leak across the process and tests are isolated; `Handler()` returns `promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})`.

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test ./pkg/metrics/ -v`
Expected: PASS.

- [ ] **Step 5: Add config + separate internal metrics listener**

`pkg/config/config.go`:

```go
	MetricsListen    string // "" = mount /metrics on the admin port (legacy); else own listener addr
	MetricsUserLabel bool   // include per-user label (PII) — default false
```
```go
		MetricsListen:    envOr("METRICS_LISTEN", "127.0.0.1:9091"),
		MetricsUserLabel: envBool("METRICS_USER_LABEL", false),
```

In `server.go`, only call `mux.Handle("/metrics", m.Handler())` when `cfg.MetricsListen == ""`. In `main.go`, when `MetricsListen != ""`, serve `m.Handler()` on that address from its own goroutine (internal-only by default). Pass `metrics.Options{UserLabel: cfg.MetricsUserLabel}` into `metrics.New`.

- [ ] **Step 6: Build + test**

Run: `go build ./... && go test ./pkg/metrics/ ./pkg/admin/ ./pkg/config/ -v`
Expected: PASS.

- [ ] **Step 7: Helm — keep metrics off the public LoadBalancer**

Remove the `prometheus.io/scrape`/`prometheus.io/port: "9090"` annotations that point Prometheus at the public admin port in `templates/deployment.yaml`. Add a metrics container port + an internal `ClusterIP` Service (or a `podMonitor`/`ServiceMonitor` value) scraping the metrics listener, and a NetworkPolicy ingress rule allowing only the monitoring namespace. Add `metrics: { listen: "0.0.0.0:9091", userLabel: false, serviceMonitor: false }` to `values.yaml` (bind `0.0.0.0` inside the pod but expose only via ClusterIP + NetworkPolicy). Document in README.

- [ ] **Step 8: Commit**

```bash
git add pkg/metrics pkg/config pkg/admin cmd/evan-proxy/main.go helm README.md
git commit -m "serve metrics on an internal listener and drop user-label PII"
```

---

## Phase 4 — TLS + secure cookie

**Files:**
- Modify: `pkg/config/config.go` (`ForceHTTPS`, autocert settings)
- Create: `pkg/admin/cookie.go` + `pkg/admin/cookie_test.go` (`sessionCookieFor`, security headers)
- Modify: `pkg/admin/api.go` (use `sessionCookieFor`; add `secureCookies`)
- Modify: `pkg/admin/server.go` (security-headers + optional HTTPS-redirect middleware)
- Modify: `cmd/evan-proxy/main.go` (optional built-in autocert TLS)
- Create: `helm/evan-proxy/templates/ingress.yaml` TLS block; `values.yaml` ingress.tls
- Modify: `README.md`

- [ ] **Step 1: Write the failing cookie test**

`pkg/admin/cookie_test.go`:

```go
func TestSessionCookieFor_SecureFlag(t *testing.T) {
	c := sessionCookieFor("tok", true)
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected secure httponly strict cookie, got %+v", c)
	}
	if c.Name != sessionCookie || c.Value != "tok" {
		t.Fatalf("unexpected cookie identity: %+v", c)
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./pkg/admin/ -run TestSessionCookieFor -v`
Expected: FAIL — undefined `sessionCookieFor`.

- [ ] **Step 3: Implement cookie + headers helpers**

`pkg/admin/cookie.go`:

```go
package admin

import "net/http"

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
```

Refactor `handleLogin`/`handleLogout` to use `sessionCookieFor(token, a.secureCookies)` (logout: same helper with `MaxAge:-1`, or a `clearedSessionCookie(secure)` sibling). Add `secureCookies bool` to `api`, set from `cfg.ForceHTTPS` in `NewServer`.

- [ ] **Step 4: Run and confirm pass; wrap the mux with `securityHeaders`**

In `NewServer`, return `securityHeaders(mux, cfg.ForceHTTPS)` (wrap in the `Server` struct's handler). Run: `go test ./pkg/admin/ -v` → PASS.

- [ ] **Step 5: Config for ForceHTTPS + autocert**

```go
	ForceHTTPS   bool   // set Secure cookie + HSTS; assume TLS terminates in front or via autocert
	AutocertHost string // if set, terminate TLS in-process via Let's Encrypt for this hostname
	AutocertDir  string // cert cache dir (persistent volume)
```
```go
		ForceHTTPS:   envBool("FORCE_HTTPS", false),
		AutocertHost: os.Getenv("AUTOCERT_HOST"),
		AutocertDir:  envOr("AUTOCERT_DIR", "/data/evan-proxy/autocert"),
```

- [ ] **Step 6: Optional built-in autocert path in `main.go`**

When `cfg.AutocertHost != ""`, use `golang.org/x/crypto/acme/autocert`:

```go
	if cfg.AutocertHost != "" {
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.AutocertHost),
			Cache:      autocert.DirCache(cfg.AutocertDir),
		}
		adminSrv.TLSConfig = mgr.TLSConfig()
		go http.ListenAndServe(":80", mgr.HTTPHandler(nil)) // ACME challenge + HTTP->HTTPS redirect
		go func() {
			if err := adminSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				logger.Fatalf("admin", "tls: %v", err)
			}
		}()
	} else {
		// existing plain ListenAndServe path (TLS terminated by ingress)
	}
```

Run `go mod tidy` to pull `acme/autocert`. This gives the Raspberry-Pi single-binary deployment a valid Let's Encrypt cert with zero manual cert files; the k8s deployment leaves `AutocertHost` empty and terminates TLS at the ingress.

- [ ] **Step 7: Helm ingress TLS**

Add to `values.yaml` `ingress:` an example:

```yaml
  tls:
    - secretName: evan-proxy-tls
      hosts:
        - proxy.example.com
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
```

In `templates/ingress.yaml` render a `spec.tls:` block when `.Values.ingress.tls` is set. Set `FORCE_HTTPS: "true"` via values when TLS is in front. Stop defaulting `service.type` to `LoadBalancer` exposing 9090 raw — document that admin should be reached through the ingress (or a private LB). Document all of this in README with both deployment recipes.

- [ ] **Step 8: Build + full test + helm lint**

Run: `go build ./... && go test ./... && helm lint helm/evan-proxy`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add pkg helm cmd README.md go.mod go.sum
git commit -m "add TLS support: secure cookie, HSTS, ingress TLS, optional autocert"
```

---

## Phase 5 — Device token model + QR pairing (server)

**Model:** A `device_tokens` table stores the **SHA-256 of each token** (never the token itself), plus a name and timestamps. Pairing is two steps: (1) an authenticated admin creates a short-lived, single-use **enrollment code** (kept in memory, like sessions); the UI renders it as a QR encoding an `evanproxy://pair?host=<host>&code=<code>` deep link. (2) The device POSTs the code to `/api/pair` and receives a long-lived bearer token **once**. Protected endpoints then accept either the session cookie (browser) or `Authorization: Bearer <token>` (app) — **except device management**: `/api/devices/enroll` and `/api/devices` (list/revoke) accept only the session cookie, so a leaked device token cannot enroll a replacement for itself or revoke other devices, and revoking a token is a complete kill. Phase 6 must not expect the iOS app to reach these endpoints with its bearer token.

**Files:**
- Create: `pkg/userdb/devicetokens.go` + `_test.go` (token store)
- Create: `pkg/admin/enroll.go` + `_test.go` (in-memory enrollment codes)
- Create: `pkg/admin/devices.go` + `_test.go` (enroll / pair / list / revoke handlers, bearer auth)
- Modify: `pkg/admin/api.go` (`requireSession` also accepts bearer tokens)
- Modify: `pkg/admin/server.go` (new routes)
- Modify: `api/openapi.yaml` + `ios/Sources/EvanProxy/openapi.yaml` (new operations, `bearerAuth` scheme)
- Modify: `pkg/admin/static/index.html` + `style.css` (Devices panel + QR)

- [ ] **Step 1: Write the failing token-store test**

`pkg/userdb/devicetokens_test.go`:

```go
func TestDeviceTokens_CreateValidateRevoke(t *testing.T) {
	d := openTestDB(t)
	tok, id, err := d.CreateDeviceToken("Chris's iPhone")
	if err != nil { t.Fatal(err) }
	if tok == "" || id == "" { t.Fatal("empty token/id") }

	name, ok := d.ValidateDeviceToken(tok)
	if !ok || name != "Chris's iPhone" { t.Fatalf("validate failed: %q %v", name, ok) }

	if _, ok := d.ValidateDeviceToken("bogus"); ok { t.Fatal("bogus token validated") }

	if err := d.RevokeDeviceToken(id); err != nil { t.Fatal(err) }
	if _, ok := d.ValidateDeviceToken(tok); ok { t.Fatal("revoked token still valid") }
}
```

(`openTestDB` mirrors `setupAPI`'s `userdb.Open(filepath.Join(t.TempDir(), "u.db"), lg)`.)

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./pkg/userdb/ -run TestDeviceTokens -v`
Expected: FAIL — methods undefined.

- [ ] **Step 3: Implement the token store**

Create `pkg/userdb/devicetokens.go`. Add the table in `Open()` alongside the users table:

```go
	CREATE TABLE IF NOT EXISTS device_tokens (
		id           TEXT PRIMARY KEY,
		token_sha256 BLOB NOT NULL UNIQUE,
		name         TEXT NOT NULL DEFAULT '',
		created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
		last_seen_at DATETIME
	)
```

```go
type DeviceToken struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

// CreateDeviceToken mints a random 32-byte token, stores only its SHA-256,
// and returns (plaintextToken, id). The plaintext is shown to the caller once.
func (d *DB) CreateDeviceToken(name string) (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	id := base64.RawURLEncoding.EncodeToString(sum[:8])
	if _, err := d.db.Exec(
		"INSERT INTO device_tokens (id, token_sha256, name) VALUES (?, ?, ?)",
		id, sum[:], name); err != nil {
		return "", "", fmt.Errorf("inserting device token: %w", err)
	}
	return token, id, nil
}

// ValidateDeviceToken returns the device name for a valid token and updates
// last_seen_at. Uses a constant-time compare against the stored hash.
func (d *DB) ValidateDeviceToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	var name string
	err := d.db.QueryRow(
		"SELECT name FROM device_tokens WHERE token_sha256 = ?", sum[:]).Scan(&name)
	if err != nil {
		return "", false
	}
	d.db.Exec("UPDATE device_tokens SET last_seen_at = datetime('now') WHERE token_sha256 = ?", sum[:])
	return name, true
}

func (d *DB) ListDeviceTokens() ([]DeviceToken, error) { /* SELECT id,name,created_at,last_seen_at ORDER BY created_at */ }
func (d *DB) RevokeDeviceToken(id string) error        { /* DELETE ... WHERE id = ?; ErrUnknownDevice on 0 rows */ }
```

`crypto/rand`, `crypto/sha256`, `encoding/base64` are already imported in `userdb.go`. Lookup by unique `token_sha256` is O(1) via the UNIQUE index; the compare is a hash equality on a random 256-bit value, so it is not password-guessable and no argon2 is needed.

- [ ] **Step 4: Run and confirm pass**

Run: `go test ./pkg/userdb/ -run TestDeviceTokens -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/userdb/devicetokens.go pkg/userdb/devicetokens_test.go
git commit -m "add hashed device-token store"
```

- [ ] **Step 6: Write failing enrollment-code test**

`pkg/admin/enroll_test.go`:

```go
func TestEnrollStore_SingleUseAndExpiry(t *testing.T) {
	es := newEnrollStore(50 * time.Millisecond)
	code := es.create()
	if !es.consume(code) { t.Fatal("first consume should succeed") }
	if es.consume(code) { t.Fatal("code must be single-use") }

	code2 := es.create()
	time.Sleep(60 * time.Millisecond)
	if es.consume(code2) { t.Fatal("expired code must not consume") }
}
```

- [ ] **Step 7: Run/confirm fail, then implement `enrollStore`**

`pkg/admin/enroll.go`: an in-memory `map[string]time.Time` guarded by a mutex, `create()` returns a random URL-safe code (reuse the 16-byte `crypto/rand` + `base64.RawURLEncoding` pattern) with `expiresAt = now+ttl`, `consume(code)` atomically checks non-expired + deletes (single use). Mirror `SessionStore`'s background cleanup goroutine + `Stop()`.

Run: `go test ./pkg/admin/ -run TestEnrollStore -v` → PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/admin/enroll.go pkg/admin/enroll_test.go
git commit -m "add single-use enrollment code store"
```

- [ ] **Step 9: Write failing handler tests (enroll/pair/list/revoke + bearer auth)**

`pkg/admin/devices_test.go` — cover: authed `POST /api/devices/enroll` returns a `code` + `pair_url`; `POST /api/pair` with that code returns a `token`; a second `/api/pair` with the same code is 401; a protected endpoint (`/api/users`) succeeds with `Authorization: Bearer <token>` and no cookie; `DELETE /api/devices?id=` then the same bearer token is 401; `/api/pair` with a bad code is 401. Use `setupAPI` extended with `devices *enrollStore` and the `users` store already present.

- [ ] **Step 10: Run/confirm fail; implement handlers + bearer auth**

`pkg/admin/devices.go`:

```go
func (a *api) handleEnroll(w http.ResponseWriter, r *http.Request) {
	// POST only; requires session (admin). Creates a code, builds the pair URL.
	code := a.enroll.create()
	host := r.Host
	resp := map[string]string{
		"code":       code,
		"pair_url":   "evanproxy://pair?host=" + url.QueryEscape(host) + "&code=" + url.QueryEscape(code),
		"expires_in": "300",
	}
	writeJSON(w, resp)
}

func (a *api) handlePair(w http.ResponseWriter, r *http.Request) {
	// POST, NO session — authenticated by the single-use enrollment code.
	var req struct{ Code, DeviceName string `json:"code"`; }
	json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req)
	if req.Code == "" || !a.enroll.consume(req.Code) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	name := req.DeviceName
	if name == "" { name = "device" }
	token, _, err := a.users.CreateDeviceToken(name)
	if err != nil { http.Error(w, "internal error", 500); return }
	writeJSON(w, map[string]string{"token": token})
}

func (a *api) handleListDevices(w http.ResponseWriter, r *http.Request) { /* GET: a.users.ListDeviceTokens() */ }
func (a *api) handleRevokeDevice(w http.ResponseWriter, r *http.Request) { /* DELETE ?id=: a.users.RevokeDeviceToken */ }
```

Extend auth in `pkg/admin/api.go` so protected routes accept a bearer token. Add a helper and use it inside `requireSession`:

```go
func (a *api) authed(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if _, ok := a.users.ValidateDeviceToken(strings.TrimPrefix(h, "Bearer ")); ok {
			return true
		}
	}
	if c, err := r.Cookie(sessionCookie); err == nil && a.sessions.Validate(c.Value) {
		return true
	}
	return false
}
```

`requireSession` becomes: `if !a.authed(r) { w.WriteHeader(401); return }; next(w,r)`. Note `/api/pair` and `/api/devices/enroll` differ: `enroll` is behind `requireSession` (admin only); `pair` is public but gated by the single-use code.

- [ ] **Step 11: Run and confirm pass**

Run: `go test ./pkg/admin/ -v`
Expected: PASS.

- [ ] **Step 12: Wire routes**

In `server.go`:

```go
	mux.HandleFunc("/api/devices/enroll", a.requireSession(a.handleEnroll))
	mux.HandleFunc("/api/devices", a.requireSession(a.handleDevices)) // GET list, DELETE revoke
	mux.HandleFunc("/api/pair", a.handlePair)                          // public, code-gated
```

- [ ] **Step 13: OpenAPI + Devices UI**

Add `enrollDevice`, `pairDevice`, `listDevices`, `revokeDevice` operations and a `bearerAuth` (`type: http, scheme: bearer`) security scheme to both `api/openapi.yaml` and `ios/Sources/EvanProxy/openapi.yaml`. Add a "Devices" panel to `pkg/admin/static/index.html`: an "Add device" button that calls `/api/devices/enroll`, renders the returned `pair_url` as a QR (vendor a tiny MIT QR lib into `static/`, or generate the QR server-side as SVG to avoid adding JS deps — prefer server-side SVG at `GET /api/devices/enroll` returning `image/svg+xml` behind the session), and a list from `/api/devices` with per-row revoke. Escape all rendered device names with the existing `escHtml`.

- [ ] **Step 14: Build + full test**

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 15: Commit**

```bash
git add pkg/admin api/openapi.yaml ios/Sources/EvanProxy/openapi.yaml
git commit -m "add QR enrollment, device pairing, and bearer-token auth"
```

---

## Phase 6 — iOS QR pairing

**Files:**
- Create: `ios/Sources/EvanProxy/Features/Pairing/QRScannerView.swift` (AVFoundation camera)
- Create: `ios/Sources/EvanProxy/Features/Pairing/PairingModel.swift` (deep-link parse + `/api/pair` call)
- Modify: `ios/Sources/EvanProxy/Networking/AuthStore.swift` (store token, not password)
- Modify: `ios/Sources/EvanProxy/Networking/APIClientFactory.swift` (bearer-header middleware)
- Modify: `ios/Sources/EvanProxy/App/EvanProxyApp.swift` (handle `evanproxy://pair` URL)
- Modify: `ios/Sources/EvanProxy/Features/Login/LoginView.swift` (add "Scan QR to pair" entry)
- Create: `ios/Tests/EvanProxyTests/PairingModelTests.swift`

- [ ] **Step 1: Write failing deep-link parse test**

`PairingModelTests.swift`:

```swift
func testParsePairURL() throws {
    let url = URL(string: "evanproxy://pair?host=proxy.example.com&code=abc123")!
    let p = try PairingModel.parse(url)
    XCTAssertEqual(p.host, "proxy.example.com")
    XCTAssertEqual(p.code, "abc123")
}
```

- [ ] **Step 2: Run/confirm fail (Xcode or `swift test` in `ios/`)**

Run: `cd ios && swift test --filter PairingModelTests`
Expected: FAIL — `PairingModel.parse` undefined.

- [ ] **Step 3: Implement parse + pair call**

`PairingModel.swift`: `static func parse(_ url: URL) throws -> (host: String, code: String)` using `URLComponents`; `func pair(host:code:deviceName:)` that builds a base URL `https://<host>`, POSTs `{code, device_name}` to `/api/pair`, decodes `{token}`, stores it via `AuthStore`, and sets `ServerConfig.baseURL`. Device name defaults to `UIDevice.current.name`.

- [ ] **Step 4: Run/confirm pass**

Run: `cd ios && swift test --filter PairingModelTests`
Expected: PASS.

- [ ] **Step 5: Store token instead of password; add bearer middleware**

In `AuthStore.swift`, keep the token in the Keychain under `"deviceToken"` and drop password storage for the paired path (leave username/password login as a fallback for existing installs). In `APIClientFactory.swift`, add a `ClientMiddleware` that sets `Authorization: Bearer <token>` from the Keychain on every request; keep `ReauthMiddleware` only for the legacy password path. A revoked token → server 401 → app routes to the pairing screen (not silent reauth, since there's no password).

- [ ] **Step 6: QR scanner + deep-link handling + login entry point**

`QRScannerView.swift`: `AVCaptureSession` with `AVCaptureMetadataOutput` (`.qr`), emits the scanned string; feed it to `PairingModel`. In `EvanProxyApp.swift` add `.onOpenURL { url in ... }` to handle `evanproxy://pair` when scanned by the system Camera app. Add a "Scan QR to pair" button on `LoginView`. Add the `evanproxy` URL scheme + `NSCameraUsageDescription` to the app's Info settings in `ios/App/project.yml`.

- [ ] **Step 7: Build the iOS package/tests**

Run: `cd ios && swift build && swift test`
Expected: PASS (the generated-client smoke test picks up the new `bearerAuth`/pair operations).

- [ ] **Step 8: Commit**

```bash
git add ios
git commit -m "add QR pairing flow and bearer-token auth to iOS app"
```

---

## Roll-up verification (after all phases)

- [ ] `go build ./... && go test ./...` — all Go packages green.
- [ ] `helm lint helm/evan-proxy && helm template helm/evan-proxy` — renders with TLS, internal metrics, opt-in pprof.
- [ ] `cd ios && swift build && swift test` — iOS package green.
- [ ] Manual smoke: deploy with `FORCE_HTTPS=true` behind an ingress cert; confirm `/debug/pprof` is unreachable on the public host, `/metrics` returns 404 on the public host, repeated bad logins yield 429, and the iOS app pairs by scanning the admin QR and works over the public URL.
- [ ] Update the project wiki: new env vars, the QR pairing flow, and the "safe public exposure" checklist (per CLAUDE.md wiki guidance).

## Self-review notes

- **Spec coverage:** login rate limiting (P1), pprof opt-in (P2), `/metrics` safety (P3), TLS incl. admin/UX + iOS ATS (P4), QR per-device tokens end-to-end (P5+P6) — all four of chris's asks plus the audit's High/Medium items are covered.
- **Cross-phase type consistency:** `sessionCookieFor(token, secure)` is introduced in P4 and referenced from P1's `handleLogin` — when executing in order, P1 uses the current inline cookie and P4 does the refactor (noted at P1 Step 11). `CreateDeviceToken`/`ValidateDeviceToken`/`RevokeDeviceToken`/`ListDeviceTokens` names are used identically in P5 store, handlers, and P6 client.
- **Sequencing:** P5 depends on P1 (shared limiter/authed wiring) and P4 (bearer tokens require TLS); P6 depends on P5's endpoints + OpenAPI. P1–P4 are independent and can land in any order.
