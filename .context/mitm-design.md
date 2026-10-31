# evan-proxy MITM — refined design

Status: approved, ready for implementation planning.
Supersedes: `.context/mitm-plan.md` (background and problem framing live there).

## Problem recap

evan-proxy's per-user disable/downtime control fails on iOS Safari. With `ProxyPACFallbackAllowed=true` (required for airport captive portals), Safari silently retries DIRECT on every proxy failure shape we tested: closed listener, 200+FIN, 200+RST, 403, and 200+TLS-fatal-alert (verified 2026-10-28). The workaround — flipping fallback off — breaks airplane captive portals.

Direction: terminate TLS at the proxy during blocks, serve a real HTTPS block page with a forged leaf cert chaining to a device-trusted root CA. Safari sees a successful HTTPS exchange with the destination, not a proxy failure, and has no reason to fall back DIRECT.

## Decisions (locked)

| # | Decision |
|---|---|
| MITM engagement | Block-only (user disabled or in downtime). Normal operation stays CONNECT passthrough. |
| CA key storage | Vault via External Secrets. Proxy authenticates via Kubernetes auth. |
| SimpleMDM integration | Lives inside evan-proxy. API key, device ID, profile ID stored in Vault, writable from admin UI. |
| Install-status gate | None. MITM engages blindly. Uninstalled CA → cert error, which also blocks (Safari treats cert error as terminal). |
| Allowlist under block | Passthrough. Apple services, Push, iCloud etc. keep working during a block so iMessage/Find My survive. |
| SimpleMDM profile shape | Single proxy-owned profile (the Snell Family Kids profile). Proxy becomes the only writer long-term. |
| v1 profile authoring | B3: edit the CA payload only on each rotation. Full ownership comes later as a separate project. |
| Allowlist storage | SQLite + admin UI, seeded on first boot from helm values. Updates live without redeploy. |

## Architecture

Three new packages inside evan-proxy, each with a clear single purpose:

- **`pkg/mitm`** — CA key loading, leaf cert minting + LRU cache, TLS handshake over a hijacked CONNECT, block-page handler. Pure Go, no state outside the LRU and the CA keypair.
- **`pkg/mdm`** — SimpleMDM client. Fetches current profile, mutates the CA payload, uploads, pushes. Also exposes install-status for the admin UI readout.
- **`pkg/allowlist`** — SQLite-backed hostname matcher. Suffix-match with wildcards. Seeded from helm values on first boot.

Plus a shared Vault client:

- **`pkg/vault`** — thin wrapper around `github.com/hashicorp/vault/api`. Logs in via k8s auth, renews, exposes `Get`/`Put`.

The existing `pkg/proxy/connect.go` grows one new branch after the downtime check: if the user is blocked and the host is not allowlisted, hand off to `pkg/mitm` to hijack the TLS tunnel and serve the block page. Otherwise, today's CONNECT passthrough.

Admin API additions:

```
GET  /api/ca/pem                 download CA cert, PEM
GET  /api/ca/der                 download CA cert, DER
GET  /api/ca/mobileconfig        standalone single-payload mobileconfig
POST /api/ca/rotate              generate fresh CA, push to SimpleMDM

GET  /api/mdm/config             current config (never returns api_key)
PUT  /api/mdm/config             set api_key / device_id / profile_id
GET  /api/mdm/status             install status + last push timestamp
POST /api/mdm/push               manual re-push (debug)

GET  /api/allowlist              list entries
POST /api/allowlist              add entry
DELETE /api/allowlist/:id        remove entry
```

Admin UI additions (web `pkg/admin/static/index.html` and iOS via existing OpenAPI codegen):

- **CA & MDM** tab — CA cert download, "Rotate CA" button, SimpleMDM api_key / device_id / profile_id fields, install-status readout, manual push button.
- **Allowlist** tab — table + inline add, two-click delete, matches existing `inline-edit-row` conventions.

### Data flow during a blocked CONNECT to `example.com`

```
Client ──CONNECT example.com:443──▶ proxy
          proxy: auth OK, user disabled, host NOT allowlisted
          proxy: 200 Connection Established
Client ──ClientHello (SNI=example.com)──▶ proxy
          proxy: mint leaf for example.com (cache miss) signed by CA
          proxy: TLS handshake (TLS 1.2/1.3, forged cert)
Client ──GET / HTTP/1.1──▶ proxy
          proxy: static block page HTML/1.1 200
Client: Safari renders block page under example.com's URL bar
```

## `pkg/mitm` internals

### `ca.go`

```go
type CA struct {
    cert     *x509.Certificate
    certDER  []byte
    key      crypto.Signer    // ECDSA P-256
    leafKey  crypto.Signer    // ephemeral, shared across all forged leaves
    leafPub  []byte
    cache    *lru.Cache[string, *tls.Certificate]
    mu       sync.RWMutex     // only held during Rotate
}

func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
func (c *CA) Rotate(ctx context.Context, newKey crypto.Signer, newCert *x509.Certificate)
func (c *CA) ExportPEM() []byte
func (c *CA) ExportDER() []byte
```

`GetCertificate` is the `tls.Config` callback. Stdlib hands us the ClientHelloInfo (SNI included) and we return a cached or freshly-minted cert. No separate "accept CONNECT then read ClientHello" dance — the stdlib's TLS server handles that once we start it on the hijacked conn.

### Leaf minting

- **Shared leaf private key** generated at proxy startup (ECDSA P-256, ~1ms). Every forged cert reuses the same key. Only the certificate is per-SNI. This is standard practice (mitmproxy, squid-ssl-bump); iOS validates the chain, not SPKI uniqueness.
- **LRU cache** keyed on SNI string, bounded by count (~1000 entries), in-memory only. Reads under RWMutex, writes rare. No disk cache, no shared cache across pods.
- **Cost per blocked request**: cache hit → zero; cache miss → ~2ms ECDSA sign on commodity CPU. Undetectable to a human.
- **Template** (`mint.go`):
  - Serial: random 128-bit
  - NotBefore: now − 1h (clock skew)
  - NotAfter: now + 7d
  - Subject: CN = SNI
  - SAN: DNS = SNI; empty SNI → IP SAN from CONNECT target host if parseable, else `no-sni.invalid`
  - KeyUsage: DigitalSignature, KeyEncipherment
  - ExtKeyUsage: ServerAuth
  - Signed by CA key, public key = shared leaf pub

### `hijack.go`

```go
func (m *MITM) ServeBlockPage(conn net.Conn, host, user string) error {
    tlsConn := tls.Server(conn, &tls.Config{
        GetCertificate: m.ca.GetCertificate,
        MinVersion:     tls.VersionTLS12,
    })
    if err := tlsConn.Handshake(); err != nil { return err }
    defer tlsConn.Close()
    return m.servePage(tlsConn, host, user)
}
```

Called from `connect.go` after the proxy writes `200 Connection Established`. Everything downstream is a normal `net/http` server on top of `tlsConn`.

### Block page (`blockpage.go` + `assets/pancho.jpg`)

- Static HTML, embedded via `//go:embed`. No JS, no external requests.
- JPEG of Pancho embedded as a `data:image/jpeg;base64,...` URL inside the HTML so there is exactly one response — no subresource request.
- Served as `200 OK` (not 403) so Safari renders it rather than showing its own error chrome.
- Headers: `Cache-Control: no-store`, `Content-Type: text/html; charset=utf-8`.
- Favicon as inline SVG paw via `<link rel="icon" href="data:image/svg+xml,...">`.
- JPEG resized once at commit time to ~800px wide, 75% quality (~60–80KB).

Copy:

```
          [photo of Pancho, head-tilt]

              Pancho says no.

       example.com is off-limits
         while your internet is
                paused.

           Paused at 3:42 PM
```

Palette: warm cream background (`#faf5ec`), warm brown headings (`#5c3a1e`), system font stack. Destination host rendered in monospace. Timestamp templated server-side at serve time.

## `pkg/allowlist`

### Schema (migration in `pkg/userdb`)

```sql
CREATE TABLE IF NOT EXISTS mitm_allowlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern     TEXT    NOT NULL UNIQUE,
    note        TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    created_by  TEXT    NOT NULL DEFAULT 'seed'
);
CREATE INDEX IF NOT EXISTS idx_mitm_allowlist_pattern ON mitm_allowlist(pattern);
```

Single table, no per-user allowlist in v1.

### Seeding on `userdb.Open()`

After migration: count rows. If zero, insert the baseline from `mitm.allowlistDefaults` with `created_by='seed'`. If non-zero, do nothing — operator may have deleted a seed entry on purpose.

Baseline (Apple's standard "must not be MITM'd" set — software updates, push, iCloud, App Store, carrier bundles):

```
*.apple.com
*.icloud.com
*.push.apple.com
*.mzstatic.com
*.gc.apple.com
*.cdn-apple.com
*.itunes.apple.com
*.apps.apple.com
*.aaplimg.com
mesu.apple.com
gs.apple.com
xp.apple.com
configuration.apple.com
gdmf.apple.com
```

### Matcher

```go
type List struct {
    db        *userdb.DB
    mu        sync.RWMutex
    exact     map[string]struct{}
    wildcards []string         // leading-dot form, e.g. ".apple.com"
    version   uint64
}

func (l *List) Allow(host string) bool
func (l *List) Reload(ctx context.Context) error
func (l *List) All() []Entry
func (l *List) Add(ctx context.Context, pattern, note, who string) error
func (l *List) Delete(ctx context.Context, id int64) error
```

- Normalize input: lowercase, strip trailing dot, strip port.
- Exact match map first, then scan wildcards (`.apple.com` matches both `anything.apple.com` and `apple.com`).
- Writes bump `version` and swap the maps under write lock — simple, no cache-invalidation bugs.
- Lookup cost: O(1) + O(n_wildcards). n is <50.

### Connect-path hook (`pkg/proxy/connect.go`)

After the existing downtime check:

```go
blocked := h.downtimeChecker != nil && h.downtimeChecker.IsInDowntime(user)
if !blocked {
    h.connectTunnel(conn, bufrw, r.Context(), start, clientIP, host, user)
    return
}

if h.allowlist.Allow(host) {
    h.connectTunnel(conn, bufrw, r.Context(), start, clientIP, host, user)
    return
}

conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
if err := h.mitm.ServeBlockPage(conn, host, user); err != nil {
    h.logger.Log(logging.Entry{..., Event: "mitm_error", Error: err.Error()})
}
```

Also log `mitm_served` on success so the live log stream shows which hosts the kid is hitting during a block — useful signal for "add X to the allowlist" bug reports.

### Relationship to `pkg/acl`

The existing ACL is a denylist for all users ("block these hosts outright"). The new allowlist is semantically different — "bypass MITM for these hosts during a block." They do not overlap and should not share code or a UI tab.

## `pkg/mdm` (SimpleMDM)

### Config (in Vault)

```
secret/data/evan-proxy/mdm:
  api_key:    <SimpleMDM key, HTTP Basic username, empty password>
  device_id:  "123456"       # Evan's device
  profile_id: "789012"       # the Snell Family Kids profile
```

Device ID and profile ID are config, not auto-discovered. Operator sets them once via admin UI; they rarely change. A device-picker UI listing SimpleMDM devices by name is a nice follow-up but not v1.

### Package shape

```go
type Client struct { ... }

func (c *Client) GetProfile(ctx context.Context) (*Profile, error)
func (c *Client) UpdateProfile(ctx context.Context, p *Profile) error
func (c *Client) PushProfile(ctx context.Context) error
func (c *Client) GetDeviceInstallStatus(ctx context.Context) (*InstallStatus, error)
```

Hand-rolled HTTP, 15s timeout, no SDK dependency. Five endpoints, HTTP Basic auth.

### Profile mutation (B3 path)

Pure function, golden-file testable:

```go
func SpliceCA(mobileconfig []byte, caDER []byte, caName string) ([]byte, error)
```

Finds or inserts the single `com.apple.security.root` payload in the plist, swaps `PayloadContent` for the new CA DER, bumps `PayloadVersion`. No signing (SimpleMDM re-signs on upload if the profile is marked signed; unsigned stays unsigned — iOS accepts both via MDM).

Inserted CA payload:

```xml
<dict>
    <key>PayloadType</key>           <string>com.apple.security.root</string>
    <key>PayloadIdentifier</key>     <string>com.chrissnell.evanproxy.ca</string>
    <key>PayloadUUID</key>           <string>...stable UUID, hardcoded as a Go constant at implementation time...</string>
    <key>PayloadVersion</key>        <integer>1</integer>
    <key>PayloadDisplayName</key>    <string>evan-proxy CA</string>
    <key>PayloadDescription</key>    <string>Root certificate for evan-proxy TLS inspection</string>
    <key>PayloadContent</key>        <data>...base64 CA DER...</data>
</dict>
```

**Stable `PayloadIdentifier` and `PayloadUUID`.** Changing them on rotation causes iOS to treat the new payload as a *new* cert and leave the old one trusted too, polluting the trust store. Fixed UUID = in-place replacement.

### Rotation flow

```
1. Generate new ECDSA P-256 CA keypair + 10y self-signed cert
2. Write to Vault: secret/data/evan-proxy/ca (key_pem, cert_pem)
3. mdm.GetProfile() → current mobileconfig
4. mdm.SpliceCA(mobileconfig, newCertDER, "evan-proxy CA v{serial}")
5. mdm.UpdateProfile() → upload the spliced blob
6. mdm.PushProfile() → tell SimpleMDM to install on device_id now
7. ca.Rotate(newKey, newCert) → swap under write lock, flush LRU
8. Keep OLD cert in a "grace" slot for 60s so in-flight TLS handshakes don't error mid-stream
```

Step 7 is deliberately after step 6: if SimpleMDM push fails, we don't want to be minting certs the device can't validate. Fail the whole rotate operation, surface the error to the admin UI, leave the old CA in place. Idempotent — operator can retry.

### Install-status readout

Not in the hot path. Admin UI's CA tab polls `/api/mdm/status` every 10s while open, which calls `GetDeviceInstallStatus`. Shows "Pancho CA installed on Evan's iPad: ✓ (as of 10:14:03)" or "⚠ Not installed — push attempted 2m ago". Purely informational; the proxy's block path never consults it.

### Error handling

- SimpleMDM down: UpdateProfile/PushProfile return errors with API response body. Admin UI surfaces inline. Vault is the source of truth; MDM is a mirror.
- 401: "Check your API key" surfaces to admin UI.
- 429: honor `Retry-After` for one retry. SimpleMDM's 1 req/sec limit is nowhere near our usage.

## Vault wiring, Helm, bootstrap order

### Vault paths

```
secret/data/evan-proxy/ca   {key_pem, cert_pem}
secret/data/evan-proxy/mdm  {api_key, device_id, profile_id}
```

### Vault policy `evan-proxy-rw`

```hcl
path "secret/data/evan-proxy/ca"  { capabilities = ["read", "create", "update"] }
path "secret/data/evan-proxy/mdm" { capabilities = ["read", "create", "update"] }
```

### Kubernetes auth role `evan-proxy`

- Namespace: `evan-proxy`
- ServiceAccount: `evan-proxy`
- Policies: `evan-proxy-rw`
- Token TTL: 1h, renewable

### `pkg/vault` client

Thin wrapper around `github.com/hashicorp/vault/api`:

```go
type Client struct { ... }

func New(ctx context.Context, cfg Config) (*Client, error)
func (c *Client) Get(ctx context.Context, path string) (map[string]any, error)
func (c *Client) Put(ctx context.Context, path string, data map[string]any) error
```

Reads the pod's SA token from `/var/run/secrets/kubernetes.io/serviceaccount/token`, logs into Vault, caches token, runs a renew loop in a goroutine. Vault unreachable at startup → readiness probe fails → k8s restarts.

### Helm chart changes

New `values.yaml` block:

```yaml
mitm:
  enabled: true
  vaultAddr: "http://vault.vault.svc:8200"
  vaultRole: "evan-proxy"
  leafCertTTL: "168h"
  caCertTTL: "87600h"
  allowlistDefaults:
    - "*.apple.com"
    - "*.icloud.com"
    - "*.push.apple.com"
    - "*.mzstatic.com"
    - "*.gc.apple.com"
    - "*.cdn-apple.com"
    - "*.itunes.apple.com"
    - "*.apps.apple.com"
    - "*.aaplimg.com"
    - "mesu.apple.com"
    - "gs.apple.com"
    - "xp.apple.com"
    - "configuration.apple.com"
    - "gdmf.apple.com"
```

New templates:
- `templates/serviceaccount.yaml` — the SA the Vault role binds to.
- `templates/configmap-mitm.yaml` — rendered allowlist defaults + Vault config → mounted at `/etc/evan-proxy/mitm.yaml`.

Deployment additions:
- `serviceAccountName: {{ include "evan-proxy.fullname" . }}`
- Env: `VAULT_ADDR`, `VAULT_ROLE`

NetworkPolicy additions (when enabled):
- Egress allow to `vault.vault.svc:8200`
- Egress allow to `a.simplemdm.com:443`

### Separate kube repo (`~/kube/apps/evan-proxy/`)

Three new YAMLs applied by hand (or GitOps):
- `vault-policy.yaml` — Vault Policy
- `vault-role.yaml` — k8s auth role
- `values.yaml` — production override with `mitm.enabled: true`

### Bootstrap order (fresh install)

```
1. Apply Vault policy + k8s auth role (one-time)
2. helm upgrade evan-proxy ...
3. Pod starts, reads SA token, logs into Vault
4. Pod checks secret/data/evan-proxy/ca → empty
5. Pod generates CA keypair, writes to Vault
6. Pod continues normal startup
7. Operator opens admin UI, configures api_key / device_id / profile_id
8. Operator clicks "Push CA to Device" (one-time; later rotations auto-push)
9. Device install verified via admin UI readout
10. MITM engages on next block
```

If Vault auth isn't ready at step 3, readiness fails, k8s restarts, operator fixes step 1. Loud and correct — no partial-state footguns.

### Rollback

If MITM misbehaves in production:
- Admin UI → toggle "MITM mode: off". Falls back to today's close-the-port behavior for blocks.
- Flag is in SQLite, not helm — no redeploy needed.
- CA cert stays installed on device; harmless when nothing's hijacking.

## Testing

- `pkg/mitm/ca_test.go` — generate ephemeral CA, mint leaves for SNIs (hostname, wildcard target, IP literal, empty), verify chain validates.
- `pkg/mitm/mint_test.go` — golden-file: cert template produces stable fields given fixed inputs. Guards against template drift.
- `pkg/mitm/blockpage_test.go` — serve the handler to `httptest.ResponseRecorder`, assert body contains destination host + timestamp, correct Content-Type, no-store cache, embedded JPEG as `data:image/jpeg;base64,...`.
- `pkg/mitm/hijack_test.go` — integration using `net.Pipe()`: wire one end as "iOS", drive a real `crypto/tls` client against the CA, assert handshake succeeds and block page comes back. This is the test that would have caught every one of the five response-shape regressions.
- `pkg/allowlist/allowlist_test.go` — matcher: exact, wildcard, trailing-dot, port suffix, case fold. Reload: Add appears, Delete gone, concurrent reads during swap don't crash.
- `pkg/mdm/splice_test.go` — golden-file: fixture of a sanitized real profile. Splice CA, assert output's `com.apple.security.root` payload contains new DER and UUID is stable.
- `pkg/mdm/client_test.go` — `httptest.NewServer` stub of SimpleMDM; verify auth header shape, multipart upload, 429 retry-after.
- `pkg/proxy/connect_test.go` — extend existing table tests with "blocked user, non-allowlisted host" → MITM path and "blocked user, allowlisted host" → passthrough. Stub `mitm.Server` interface so no real TLS in connect-level test.

### Manual end-to-end checklist

1. Fresh pod boots, CA appears in Vault.
2. CA cert installs on test device via SimpleMDM push.
3. Disable Evan, visit `example.com` on Safari → Pancho renders, URL bar shows `example.com`, no cert warning.
4. Visit `appleid.apple.com` → real Apple page loads (allowlist passthrough).
5. Re-enable Evan → next page load passes through, no MITM.
6. Rotate CA → device re-pushes, old sessions survive 60s grace, new sessions use new leaf.
7. Delete allowlist entry for `*.apple.com`, re-attempt during block → cert error (expected; immediately re-add).

## Known risks

| Risk | Mitigation |
|---|---|
| iOS silently loses trust on installed CA after an OS update | Install-status readout in admin UI; re-push is one click |
| Shared leaf key leaks (pod compromise) | Rotation revokes-via-replace in minutes; no clients remember old keys |
| SimpleMDM API outage during rotation | Atomic flow: Vault write first (source of truth), MDM push fails loudly, operator retries. CA swap only after MDM succeeds. |
| New pinning-sensitive app ships in Evan's bundle | Live admin UI add, no redeploy. "Add X to allowlist" is the SOP for every "X is broken" report. |
| ClientHello without SNI | Use CONNECT target host as SAN; IP literal → IP SAN; neither → generic cert (cert warning still blocks) |
| Leaf template drift breaks iOS trust after a future iOS release | Golden-file test; manual re-verification on each major iOS release; keep template conservative |
| `MITM mode: off` kill-switch forgotten after a bad deploy | Admin UI banner when disabled; state visible in logs at startup |

## Phase ordering

Each phase ends with a deployable pod; stop early and we're still better off than today for the hosts the phases cover.

### Phase 1 — Prove the concept (1–2 days)

Bare `pkg/mitm` with a hardcoded CA from a `scratch/dev-ca.{crt,key}` file. Hardcoded "blocked user" decision. No Vault, no SimpleMDM, no admin UI for allowlist. One manual mobileconfig install on the test device. **Goal: Pancho renders in Safari during a simulated block, no PAC fallback observed.**

To avoid breaking iMessage/Push/iCloud for the PoC window, Phase 1 ships with a *hardcoded* Apple-domain bypass slice in `connect.go` matching the Phase 2 baseline. Phase 2 removes the hardcode when the real allowlist arrives.

Deliverables:
- `pkg/mitm/ca.go`, `mint.go`, `hijack.go`, `blockpage.go` with embedded Pancho JPEG
- `scripts/gen-dev-ca.sh` for throwaway CA
- Hardcoded hook in `connect.go` behind a feature flag, with hardcoded Apple-domain bypass
- Manual mobileconfig for one-off CA install
- Unit tests for `mint`, `ca`, `blockpage`, `hijack`

### Phase 2 — Allowlist (1 day)

Real `pkg/allowlist`, SQLite migration, admin API + web UI, helm-seeded defaults. Still dev CA. Verify Apple services survive a block end-to-end on the test device.

Deliverables:
- `pkg/allowlist/` with matcher + CRUD
- `pkg/userdb` migration for `mitm_allowlist` table
- Admin API `GET/POST/DELETE /api/allowlist`
- Web UI "Allowlist" tab in `pkg/admin/static/index.html`
- Helm `mitm.allowlistDefaults` block
- Connect-path integration via `allowlist.Allow(host)` gate
- Unit tests for matcher + reload semantics

### Phase 3 — Vault + production CA (1–2 days)

`pkg/vault`, k8s auth role, CA generation on first boot, admin API for CA export + rotation. SimpleMDM stubbed. Replace dev CA with Vault-sourced CA.

Deliverables:
- `pkg/vault/` client with SA-based login + renew
- Helm templates: `serviceaccount.yaml`, Vault env wiring, NetworkPolicy egress to Vault
- `vault-policy.yaml`, `vault-role.yaml` in `~/kube/apps/evan-proxy/`
- First-boot CA generation in `pkg/mitm`
- Admin API `/api/ca/{pem,der,mobileconfig,rotate}`
- Readiness probe gated on Vault auth
- Unit tests for Vault client (stub Vault), CA generation idempotency

### Phase 4 — SimpleMDM (2 days)

`pkg/mdm` with splice + client, UpdateProfile + Push + install-status, admin UI for config, full rotation flow end-to-end.

Deliverables:
- `pkg/mdm/client.go`, `splice.go` with golden-file fixture of a sanitized real profile
- Admin API `/api/mdm/{config,status,push}` + rotate hook into `POST /api/ca/rotate`
- Web UI "CA & MDM" tab with api_key / device_id / profile_id fields, "Rotate CA" button, install-status readout
- NetworkPolicy egress to `a.simplemdm.com:443`
- Unit tests for splice (golden-file), client (httptest stub SimpleMDM), end-to-end rotation
- One-time operator step documented: configure api_key / device_id / profile_id in admin UI, push CA. If no profile currently exists in SimpleMDM for the target device, operator pre-creates an empty profile named "Snell Family Kids" in the SimpleMDM UI and uses that `profile_id` — the proxy will fill in the CA payload on first push.

### Phase 5 — iOS admin app (1 day)

Mirror the web admin UI's new tabs through the existing OpenAPI codegen path.

Deliverables:
- OpenAPI spec updates for the new endpoints
- Regenerated iOS client
- "CA & MDM" screen in `ios/App/Sources/`
- "Allowlist" screen in `ios/App/Sources/`
- Tests in `ios/Tests/EvanProxyTests/`

### Phase 6 — Harden + ship (1 day)

Kill-switch, admin UI banner when disabled, metrics, structured logs, re-enable PAC fallback in the Snell Family Kids profile.

Deliverables:
- `MITM mode: off` toggle in SQLite + admin UI banner
- Prometheus metrics: `evan_proxy_mitm_block_page_served_total{host}`, `evan_proxy_mitm_cert_cache_hit_total`, `evan_proxy_mitm_cert_cache_miss_total`, `evan_proxy_mdm_push_total{status}`
- Structured log events: `mitm_served`, `mitm_passthrough`, `mitm_error`, `ca_rotated`, `mdm_pushed`
- Flip `ProxyPACFallbackAllowed=true` back in the Snell Family Kids profile (verify airport captive portal recovers)
- Manual end-to-end checklist executed and signed off

## Non-goals (unchanged from `.context/mitm-plan.md`)

- Full HTTPS content filtering (future phase; v1 is reliable blocking only).
- Auto-rotating the root CA on a schedule.
- Shipping the CA to any non-family device.
- Replacing per-user enable/downtime semantics.
- Non-proxy mechanisms (Screen Time, NextDNS downtime).
