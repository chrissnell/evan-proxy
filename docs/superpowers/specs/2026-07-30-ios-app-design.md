# evan-proxy iOS app — design spec

**Status:** approved (GRA-414, 2026-07-30). Decisions A–F confirmed by the initiator.

## Goal

A native SwiftUI iOS app with full parity to the evan-proxy admin web UI, that
logs in once and stays logged in, and visually matches the web app. The primary
use case (from the README) is a parent quickly flipping a child's internet on/off
or granting a timed override, without friction.

## Confirmed decisions

| # | Decision | Choice |
|---|----------|--------|
| A | Scope | **Full parity** with the web admin UI. |
| B | Persistent login | **Keychain-stored credentials + transparent re-auth on 401.** Optional Face ID / Touch ID gate. No server change. |
| C | API client | **Generated from `api/openapi.yaml`** via `swift-openapi-generator`. The spec lands first (this PR). |
| D | Navigation | **Tab bar** — Dashboard / Users / Logs (+ Settings). |
| E | Schedule/time editing | **Native iOS pickers** styled to match. |
| F | Repo location | **`ios/` directory** inside the evan-proxy repo. |

## API surface consumed

Documented in `api/openapi.yaml` (OpenAPI 3.1). Summary:

- **Auth:** `POST /api/login` (sets `evan-proxy-session` cookie), `POST /api/logout`.
- **Users:** `GET/POST/DELETE /api/users`, `PUT /api/users/password`,
  `PUT /api/users/port`, `PUT /api/users/enabled`.
- **DNS:** `PUT /api/users/dns`, `POST /api/users/dns/test` (~5s).
- **Downtime:** `PUT /api/users/downtime`, `PUT /api/users/downtime-override`.
- **Stats:** `GET /api/stats/{top-sites,top-blocked,traffic}`.
- **Logs:** `GET /api/logs` — SSE stream of `LogEntry`.
- **System:** `GET /api/version`.

Errors are `text/plain` today; the client keys off status codes.

## Architecture

Small, independently testable units:

- **`APIClient`** — the only type that talks to the server. Generated from
  `openapi.yaml`; wrapped so it injects the session cookie and owns the
  transparent-reauth interceptor.
- **`AuthStore`** — Keychain-backed credentials + session state; re-auth-on-401
  with a single retry; explicit logout clears the Keychain; optional biometric gate.
- **`LogStream`** — SSE reader over `URLSession.bytes`, exposed as an
  `AsyncSequence<LogEntry>`; caps at ~200 lines like the web tail.
- **Feature views** — `DashboardView`, `UsersView` (+ per-user edit sheets:
  schedule, port, DNS w/ test, password, override, add/delete), `LogsView`,
  `SettingsView`. Each backed by an `@Observable` view model calling `APIClient`.
- **`Theme`** — colors, font, and shared components.

## Persistent-login flow

1. First launch → login screen.
2. On success, credentials saved to the Keychain.
3. Every request passes through the interceptor; a `401` triggers a silent
   re-login from stored credentials and one retry.
4. Explicit **logout** clears the Keychain and returns to login.
5. Optional Face ID gate on cold start.

This delivers "log in once, stays logged in" against the current session model
(24h sliding, in-memory TTL) with no server change.

## Look & feel (matching the web app)

- **Font:** bundle **Inconsolata** (same face as the web UI); app-wide, incl. chart labels.
- **Palette:** transcribe the CSS custom properties into an asset catalog with
  matched light/dark values (bg `#fff`/`#0a0a0a`, fg `#111`/`#c8c8c8`, accent
  `#2a7a5a`/`#5a9`, danger `#c44`/`#c66`, warn `#a85`/`#ca5`, override-purple
  `#7a5aa0`/`#a080c8`, graph fills/strokes). Follows **system appearance**.
- **Components:** `Box` (1px border, 2px radius, muted fill), uppercase
  letter-spaced section headers, lowercase labels, the status **dot with colored
  glow** (enabled/disabled/downtime/override), pill buttons, danger/save variants.
- **Graphs:** bandwidth + requests via **Swift Charts** (translucent area + line)
  reading `/api/stats/traffic`.

## Stack

SwiftUI, iOS 17+ (Observation, latest Swift Charts), SwiftPM. Server base URL is a
Settings field stored alongside credentials.

## Testing

- Unit: `AuthStore` (reauth-on-401, logout clears Keychain), `LogStream`
  (SSE parse + line cap), view models against a mocked `APIClient`.
- Snapshot: themed components in light/dark.
- Manual: run against a live evan-proxy instance.

## Deployment note (carried from GRA-406)

The admin port also serves unauthenticated `/metrics` and `/debug/pprof`. The app
only needs `/api/*`; the public ingress route must be restricted to `/api/*`
(and `/login`, `/`, `/static/*` for the browser). Tracked in GRA-406.

## Out of scope (YAGNI)

Multi-admin/roles, push notifications, offline caching, iPad-specific layout
(universal build is fine), Android.
