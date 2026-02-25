# evan-proxy

I built this proxy out of parental necessity.  I tried all of the prominent child web filtering solutions and they were all terrible and expensive.

All I wanted was to keep my kids away from harmful content and to be able to quickly turn internet on and off for them, but these services all required installing their sketchy MDM profile and using some crappy app.  I never knew what they were doing with my kids' info behind the scenes.

I knew I could do better.  

I would create my own MDM profile with the excellent and free [iMazing Profile Editor](https://imazing.com/profile-editor) and manage it through [SimpleMDM](https://simplemdm.com/).  I would use the profile to force my kids' phones through a proxy that I control.  I would use [NextDNS](https://nextdns.io/) (free tier) to filter out the apps and categories of websites that I didn't want them to visit. 
 
**The unsolved problem was the proxy server.**

There are a number of open-soruce proxy servers out there but none of them made it easy to turn on/off a single child's phone quickly and easily.  And none of them would let me easily set a unique DNS resolver for each child--my kids get different levels of restriction depending on their age.

**I decided to write evan-proxy.**   It's a simple and secure web proxy with per-child DNS server selection, authentication, and logging.

To make this work, follow this plan:

1. Set up *evan-proxy* on infrastructure of your choice. I run it on a homelab Kubernetes cluster and used the included Helm chart to install it, but you could easily run it on a single Raspberry Pi if you wanted.
2. Set up a user in the evan-proxy Admin UI for your child, with a [strong but easy](https://xkcd.com/936/) password.
3. Use something like the excellent [iMazing Profile Editor](https://imazing.com/profile-editor) to create a MDM profile for your child's Apple device.  
4. Configure the profile with a Global HTTP Proxy enforced.
5. Sign up for a DNS service like [NextDNS](https://nextdns.io/) and configure their DNS to your liking, blocking what you wish to block. 
6. Add that DNS server to the MDM profile to enforce its use.
7. Also, add that DNS server to the user's account in the evan-proxy Admin UI.
8. Sign up for a MDM service like [SimpleMDM](https://simplemdm.com/) to install and remotely maintain that profile.  This is what keeps your kid from reverting your restrictions.  Or, at least, it gives you a way to know when they've subverted them.
9. (optional) Set up a Prometheus dashboard to monitor proxy use and performance

## Features:
- HTTP and HTTPS (TLS) forward proxy with CONNECT tunnel support
- Per-user dedicated proxy ports with per-user DNS resolver selection
- Admin web UI for user management, live log streaming, and proxy enable/disable
- Helm chart for Kubernetes deployment
- Rate-limiting on authentication failures to prevent password brute-forcing
- DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) support
- DNS-level block detection (returns 523 for DNS-blocked domains)
- Prometheus metrics endpoint (`/metrics`)

## Screenshot

![evan-proxy admin UI](assets/screenshot.png)

## Configuration

evan-proxy is configured via environment variables. All settings have sensible defaults except for admin credentials, which are required.

### Required

| Variable | Description |
|----------|-------------|
| `ADMIN_USER` | Admin interface username |
| `ADMIN_PASSWORD` | Admin interface password (bcrypt hash) |

Generate a bcrypt hash for the admin password:

```bash
htpasswd -nbBC 10 "" 'yourpassword' | cut -d: -f2
```

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_DB_PATH` | `/data/evan-proxy/users.db` | Path to SQLite user database |
| `PROXY_USERS_FILE` | | Path to JSON seed file for initial user import |
| `ADMIN_LISTEN` | `:9090` | Admin interface listen address |
| `DNS_SERVER` | | Custom DNS resolver (e.g. `1.1.1.1:53`), empty uses system default |
| `DNS_PROTOCOL` | `plain` | DNS protocol: `plain`, `tls` (DoT), or `https` (DoH) |
| `USER_PORT_MIN` | `8081` | First per-user dedicated proxy port |
| `USER_PORT_MAX` | `8090` | Last per-user dedicated proxy port |
| `AUTH_RETRY_TIMEOUT` | `5s` | Time to hold connection open for iOS 407 auth retry |
| `CONNECT_DIAL_TIMEOUT` | `10s` | Timeout for dialing target hosts |
| `IDLE_TIMEOUT` | `300s` | TCP idle connection timeout |
| `HTTP_TIMEOUT` | `30s` | HTTP response timeout |
| `AUTH_FAIL_RATE_LIMIT` | `5` | Failed auth attempts before rate limiting kicks in |
| `AUTH_FAIL_WINDOW` | `60s` | Sliding window for rate limiting |
| `LOG_FORMAT` | `human` | Log format: `json` or `human` |

### User Seed File

On first run, if the SQLite database is empty and `PROXY_USERS_FILE` is set, users are imported from the JSON seed file:

```json
{
  "users": [
    {"username": "alice", "password": "secretpass"},
    {"username": "bob", "password": "otherpass"}
  ]
}
```

After initial import, users are managed through the admin web UI and stored in the SQLite database.

## Building

```bash
make build    # or: CGO_ENABLED=0 go build -ldflags="-s -w" -o evan-proxy ./cmd/evan-proxy
```

## Docker

```bash
make docker   # or: docker buildx build -t ghcr.io/chrissnell/evan-proxy:dev .
```

## Helm Chart

The Helm chart is in `helm/evan-proxy/`.

### Install

```bash
helm install evan-proxy ./helm/evan-proxy -f my-values.yaml
```

### Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `replicaCount` | int | `1` | Number of replicas |
| `image.repository` | string | `"ghcr.io/chrissnell/evan-proxy"` | Container image repository |
| `image.tag` | string | `"0.1.5"` | Container image tag |
| `image.pullPolicy` | string | `"IfNotPresent"` | Image pull policy |
| `imagePullSecrets` | list | `[{name: ghcr-secret}]` | Image pull secrets |
| `proxy.logFormat` | string | `"human"` | Log format: `json` or `human` |
| `proxy.idleTimeout` | string | `"300s"` | TCP idle connection timeout |
| `proxy.httpTimeout` | string | `"30s"` | HTTP response timeout |
| `proxy.connectDialTimeout` | string | `"10s"` | Timeout for dialing target hosts |
| `proxy.authRetryTimeout` | string | `"5s"` | Time to hold connection for iOS 407 retry |
| `proxy.authFailRateLimit` | int | `5` | Failed auth attempts before rate limiting |
| `proxy.authFailWindow` | string | `"60s"` | Sliding window for rate limiting |
| `proxy.dnsServer` | string | `""` | Custom DNS resolver, empty uses system default |
| `proxy.dnsProtocol` | string | `""` | DNS protocol: `plain`, `tls`, or `https` (empty = plain) |
| `proxy.userPortMin` | int | `8080` | First per-user dedicated proxy port |
| `proxy.userPortMax` | int | `8090` | Last per-user dedicated proxy port |
| `proxyUsers` | list | `[{username: "proxy", password: "CHANGEME"}]` | Seed user credentials (imported on first run) |
| `admin.listen` | string | `":9090"` | Admin interface listen address |
| `admin.user` | string | `"admin"` | Admin username |
| `admin.passwordHash` | string | `"$2y$10$CHANGEME"` | Admin password as bcrypt hash |
| `existingSecret` | string | `""` | Use a pre-created Secret instead of generating one. Must contain keys: `users.json`, `ADMIN_USER`, `ADMIN_PASSWORD` |
| `persistence.enabled` | bool | `true` | Enable persistent storage for SQLite database |
| `persistence.size` | string | `"1Gi"` | PVC size |
| `persistence.storageClass` | string | `""` | StorageClass (empty = default) |
| `service.type` | string | `"LoadBalancer"` | Kubernetes service type |
| `service.loadBalancerIP` | string | `""` | Static IP from MetalLB pool |
| `service.annotations` | object | `{}` | Service annotations |
| `service.adminPort` | int | `9090` | Service port for admin interface |
| `ingress.enabled` | bool | `false` | Enable ingress (e.g. for admin UI) |
| `ingress.className` | string | `"cloudflare-tunnel"` | Ingress class name |
| `ingress.hosts` | list | | Ingress host rules |
| `resources.requests.cpu` | string | `"100m"` | CPU request |
| `resources.requests.memory` | string | `"64Mi"` | Memory request |
| `resources.limits.cpu` | string | `"1000m"` | CPU limit |
| `resources.limits.memory` | string | `"512Mi"` | Memory limit |
| `networkPolicy.enabled` | bool | `true` | Enable Kubernetes NetworkPolicy |
| `networkPolicy.allowAllEgress` | bool | `true` | Allow all egress for CONNECT tunnels |
| `nodeSelector` | object | `{}` | Node selector |
| `tolerations` | list | `[]` | Tolerations |
| `affinity` | object | `{}` | Affinity rules |

Per-user proxy ports (`userPortMin` through `userPortMax`) are automatically exposed on both the deployment and the service. Each user is assigned a dedicated port via the admin UI.
