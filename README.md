# evan-proxy

I built this proxy out of parental necessity.  I use MDM to force my teenager's phone through a forward proxy so that I can monitor and control the content and services he accesses.  

Sadly, neither Apple Screentime nor common proxy software offerings allow you to disable a proxy with the click of a button.   Every parent of a teenager knows what this button is for.

So, I built this with tech-savvy parents in mind.

To make this work, follow this plan:

1. Set up *evan-proxy* on infrastructure of your choice. I run it on a homelab Kubernetes cluster and used the included Helm chart to install it.  You will need to expose the proxy port (and optionally, the administrator port) to the Internet so that your child's phone can connect.
1. Use something like the excellent [iMazing Profile Editor](https://imazing.com/profile-editor) to create a MDM profile for your child's Apple device.  
2. Configure the profile with a Global HTTP Proxy enforced.
3. Sign up for a DNS service like [NextDNS](https://nextdns.io/) and configure their DNS to your liking, blocking what you wish to block. 
4. Add that DNS server to the MDM profile to enforce its use.
5. Sign up for a MDM service like [SimpleMDM](https://simplemdm.com/) to install and remotely maintain that profile.  This is what keeps your kid from reverting your restrictions.  Or, at least, it gives you a way to know when they've subverted them.


## Features:
- HTTP and HTTPS (TLS) forward proxy with CONNECT tunnel support
- iOS-compatible 407 Proxy-Authentication-Required flow
- Multi-user Basic authentication
- Admin web interface for status monitoring and proxy enable/disable
- Per-IP rate limiting on authentication failures
- DNS-level block detection (returns 523 for DNS-blocked domains)
- Structured JSON or human-readable logging
- Helm chart for Kubernetes deployment

## Configuration

evan-proxy is configured via environment variables. All settings have sensible defaults except for admin credentials, which are required.

### Required

| Variable | Description |
|----------|-------------|
| `ADMIN_USER` | Admin interface username |
| `ADMIN_PASSWORD` | Admin interface password (bcrypt hash) |
| `PROXY_USERS_FILE` | Path to JSON file containing proxy user credentials (default: `/etc/evan-proxy/users.json`) |

Generate a bcrypt hash for the admin password:

```bash
htpasswd -nbBC 10 "" 'yourpassword' | cut -d: -f2
```

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_PLAIN` | `:8080` | Plain HTTP proxy listen address |
| `LISTEN_TLS` | `:443` | TLS proxy listen address (only active when TLS_CERT is set) |
| `ADMIN_LISTEN` | `:9090` | Admin interface listen address |
| `TLS_CERT` | | Path to TLS certificate file |
| `TLS_KEY` | | Path to TLS private key file |
| `DNS_SERVER` | | Custom DNS resolver (e.g. `1.1.1.1:53`), empty uses system default |
| `AUTH_RETRY_TIMEOUT` | `30s` | Time to hold connection open for iOS 407 auth retry |
| `CONNECT_DIAL_TIMEOUT` | `10s` | Timeout for dialing target hosts |
| `IDLE_TIMEOUT` | `300s` | TCP idle connection timeout |
| `HTTP_TIMEOUT` | `30s` | HTTP response timeout |
| `AUTH_FAIL_RATE_LIMIT` | `5` | Failed auth attempts before rate limiting kicks in |
| `AUTH_FAIL_WINDOW` | `60s` | Sliding window for rate limiting |
| `LOG_FORMAT` | `human` | Log format: `json` or `human` |

### Proxy Users File

The proxy users file is a JSON file with the following format:

```json
{
  "users": [
    {"username": "alice", "password": "secretpass"},
    {"username": "bob", "password": "otherpass"}
  ]
}
```

## Building

```bash
go build -o evan-proxy .
```

## Docker

```bash
docker build -t evan-proxy .
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
| `image.tag` | string | `"0.1.4"` | Container image tag |
| `image.pullPolicy` | string | `"IfNotPresent"` | Image pull policy |
| `imagePullSecrets` | list | `[{name: ghcr-secret}]` | Image pull secrets |
| `proxy.listenPlain` | string | `":8080"` | Plain HTTP proxy listen address |
| `proxy.listenTLS` | string | `":443"` | TLS proxy listen address |
| `proxy.logFormat` | string | `"human"` | Log format: `json` or `human` |
| `proxy.idleTimeout` | string | `"300s"` | TCP idle connection timeout |
| `proxy.httpTimeout` | string | `"30s"` | HTTP response timeout |
| `proxy.connectDialTimeout` | string | `"10s"` | Timeout for dialing target hosts |
| `proxy.authRetryTimeout` | string | `"30s"` | Time to hold connection for iOS 407 retry |
| `proxy.authFailRateLimit` | int | `5` | Failed auth attempts before rate limiting |
| `proxy.authFailWindow` | string | `"60s"` | Sliding window for rate limiting |
| `proxy.dnsServer` | string | `""` | Custom DNS resolver, empty uses system default |
| `proxyUsers` | list | `[{username: "proxy", password: "CHANGEME"}]` | Proxy user credentials |
| `admin.listen` | string | `":9090"` | Admin interface listen address |
| `admin.user` | string | `"admin"` | Admin username |
| `admin.passwordHash` | string | `"$2y$10$CHANGEME"` | Admin password as bcrypt hash |
| `existingSecret` | string | `""` | Use a pre-created Secret instead of generating one. Must contain keys: `users.json`, `ADMIN_USER`, `ADMIN_PASSWORD` |
| `tls.enabled` | bool | `false` | Enable TLS proxy listener |
| `tls.certManager.enabled` | bool | `false` | Use cert-manager for TLS certificates |
| `tls.certManager.issuer` | string | `"letsencrypt-prod"` | cert-manager issuer name |
| `tls.certManager.issuerKind` | string | `"ClusterIssuer"` | cert-manager issuer kind |
| `tls.existingSecret` | string | `""` | Existing TLS secret name |
| `tls.domain` | string | `""` | Domain for cert-manager Certificate resource |
| `service.type` | string | `"LoadBalancer"` | Kubernetes service type |
| `service.loadBalancerIP` | string | `""` | Static IP from MetalLB pool |
| `service.annotations` | object | `{}` | Service annotations |
| `service.plainPort` | int | `8080` | Service port for plain proxy |
| `service.tlsPort` | int | `443` | Service port for TLS proxy |
| `service.adminPort` | int | `9090` | Service port for admin interface |
| `resources.requests.cpu` | string | `"50m"` | CPU request |
| `resources.requests.memory` | string | `"32Mi"` | Memory request |
| `resources.limits.cpu` | string | `"500m"` | CPU limit |
| `resources.limits.memory` | string | `"128Mi"` | Memory limit |
| `networkPolicy.enabled` | bool | `true` | Enable Kubernetes NetworkPolicy |
| `networkPolicy.allowAllEgress` | bool | `true` | Allow all egress for CONNECT tunnels |
| `nodeSelector` | object | `{}` | Node selector |
| `tolerations` | list | `[]` | Tolerations |
| `affinity` | object | `{}` | Affinity rules |
