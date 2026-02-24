# evan-proxy

Go HTTP/CONNECT proxy with per-user auth, per-user DNS, per-user dedicated ports, ACL support, and an admin web UI.

## Project Structure

```
main.go                          # entry point
pkg/proxy/                       # core proxy handler (CONNECT, forward, per-user ports)
pkg/admin/                       # admin API + web UI (static/index.html)
pkg/userdb/                      # SQLite user database with auth caching
pkg/config/                      # configuration from env vars
pkg/acl/                         # access control lists
pkg/dns/                         # DNS resolver (plain, DoT, DoH)
pkg/auth/                        # admin auth (bcrypt)
pkg/logging/                     # structured logging
pkg/ratelimit/                   # rate limiting
pkg/stats/                       # traffic stats + SSE streaming
pkg/metrics/                     # Prometheus metrics
helm/evan-proxy/                 # Helm chart
scratch/                         # gitignored temp files
```

## Build & Test

```bash
make build     # build binary
make test      # go test ./...
go test ./...  # run all tests directly
```

## Release, Deploy, and Test Cycle

When the user says to commit, tag, push, and deploy (or any subset), follow this sequence:

1. **Run tests**: `go test ./... -count=1` — do not proceed if tests fail
2. **Commit**: stage specific files (not `git add -A`), write a descriptive commit message
3. **Tag**: increment the patch version from the latest tag (`git tag --sort=-v:refname | head -1`), e.g. v0.4.6 -> v0.4.7
4. **Push**: `git push origin main --tags`
5. **Deploy**: `make deploy` — this builds and pushes the Docker image, then runs `helm upgrade` with the git tag as image version

The `make deploy` target:
- Builds a multi-platform Docker image via `docker buildx` and pushes to `ghcr.io/chrissnell/evan-proxy`
- Runs `helm upgrade evan-proxy helm/evan-proxy -n evan-proxy -f ~/kube/evan-proxy/values.yaml --set image.tag=<VERSION>`
- VERSION comes from `git describe --tags`

Production values override file: `~/kube/evan-proxy/values.yaml` (not in repo)

## Helm Chart

- Chart location: `helm/evan-proxy/`
- Default values: `helm/evan-proxy/values.yaml`
- Deployed to namespace `evan-proxy` on the local k8s cluster
- Service type is LoadBalancer (MetalLB)
- Template-only check: `helm template evan-proxy helm/evan-proxy`

## Admin UI Rules

- **NO POPUP DIALOGS** — never use `alert()`, `confirm()`, or `prompt()` in the admin UI. All user interactions must be inline (expand edit rows, toggle buttons, inline inputs, etc.)
- Edit rows expand below the user row using the `inline-edit-row` / `inline-edit-form` pattern
- Delete uses a two-click confirm pattern (button changes to "confirm?" on first click)
- CSS classes: `inline-edit-row`, `inline-edit-cell`, `inline-edit-form`, `inline-input`, `inline-input-short`

## Key Architecture Notes

- SQLite database at `/data/evan-proxy/users.db` with WAL mode
- Auth cache: IP-based session cache for iOS/macOS CONNECT compatibility (5min TTL)
- Per-user ports: dedicated proxy ports (default 8081-8090) that skip auth — port = user identity
- Admin UI is a single-page app embedded in `pkg/admin/static/index.html`
- Tests live alongside source files (`*_test.go` in same package)
