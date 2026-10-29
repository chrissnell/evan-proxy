package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Proxy user database (SQLite)
	ProxyDBPath string

	// Admin listener
	AdminListen string

	// Metrics
	MetricsListen    string // "" = mount /metrics on the admin port (legacy); else its own listener addr
	MetricsUserLabel bool   // include the per-user label (PII) on request metrics — default false

	// Admin credentials
	AdminUser     string
	AdminPassword string // bcrypt hash

	// TLS / transport security
	ForceHTTPS   bool   // set Secure session cookie + HSTS; assume TLS terminates in front or via autocert
	AutocertHost string // if set, terminate TLS in-process via Let's Encrypt for this hostname
	AutocertDir  string // cert cache dir (persistent volume)

	// DNS
	DNSServer   string // e.g. "1.1.1.1:53", empty = system default
	DNSProtocol string // "plain", "tls", or "https" — default "plain"

	// Timeouts
	AuthRetryTimeout   time.Duration
	ConnectDialTimeout time.Duration
	IdleTimeout        time.Duration
	HTTPTimeout        time.Duration

	// Rate limiting
	AuthFailRateLimit int
	AuthFailWindow    time.Duration

	// Admin login brute-force protection
	AdminLoginRateLimit int           // per-IP failures allowed within the window
	AdminLoginWindow    time.Duration // sliding window for per-IP failures
	AdminLoginGlobalMax int           // global failure ceiling across all IPs in the window (0 = disabled)
	TrustedProxyCIDRs   []string      // CIDRs whose X-Forwarded-For is trusted; empty = trust none

	// Per-user dedicated proxy ports
	UserPortMin int // first port in range (inclusive)
	UserPortMax int // last port in range (inclusive)

	// Logging — console
	LogFormat string // "json" or "human"

	// LogHeaders enables verbose per-request header logging on the plain-HTTP
	// forward path, showing inbound headers, which hop-by-hop headers were
	// stripped, and the exact headers forwarded upstream. Diagnostic only —
	// noisy and may expose sensitive header values, so keep off by default.
	LogHeaders bool

	// Logging — network (optional, independent of console)
	LogNetMode          string        // "json-udp" or "json-http", empty = disabled
	LogNetAddr          string        // UDP: "host:port", HTTP: "http://host:port/path"
	LogNetBatchSize     int           // json-http only: max entries before flush
	LogNetFlushInterval time.Duration // json-http only: max time between flushes

	// PAC (proxy auto-config) — optional. When enabled, the proxy answers an
	// unauthenticated GET at PACPath on each proxy port with a PAC file so
	// specific domains can be routed DIRECT (bypassing the proxy) via an iOS
	// "Auto" Global HTTP Proxy. The PAC contains only routing rules — never any
	// credentials. It is served on the proxy port itself, so the PAC URL is the
	// same endpoint the client already uses.
	PACEnabled       bool     // serve the PAC endpoint
	PACPath          string   // request path the PAC is served at (default "/proxy.pac")
	PACProxyEndpoint string   // proxy "host:port" the PAC returns; empty = echo request Host
	PACBypassDomains []string // domain suffixes routed DIRECT (bypass proxy)

	// pprof profiling endpoints. Never served on the public admin port. When
	// enabled they bind a separate loopback listener (PProfListen), reachable
	// only via `kubectl port-forward`. Off by default.
	PProfEnabled bool
	PProfListen  string // "host:port" — default "127.0.0.1:6060" (loopback only)

	// DemoMode runs the full admin API and user-management flow without ever
	// binding a real per-user proxy socket. Enabling a user's proxy updates the
	// database and the API reports it as active, but no proxy listener opens and
	// no traffic is forwarded. Intended only for Apple App Store validation
	// builds — not for the shipped release.
	DemoMode bool
}

func Load() (*Config, error) {
	cfg := &Config{
		ProxyDBPath:         envOr("PROXY_DB_PATH", "/data/evan-proxy/users.db"),
		AdminListen:         envOr("ADMIN_LISTEN", ":9090"),
		MetricsListen:       envOr("METRICS_LISTEN", "127.0.0.1:9091"),
		MetricsUserLabel:    envBool("METRICS_USER_LABEL", false),
		AdminUser:           os.Getenv("ADMIN_USER"),
		AdminPassword:       os.Getenv("ADMIN_PASSWORD"),
		ForceHTTPS:          envBool("FORCE_HTTPS", false),
		AutocertHost:        os.Getenv("AUTOCERT_HOST"),
		AutocertDir:         envOr("AUTOCERT_DIR", "/data/evan-proxy/autocert"),
		DNSServer:           os.Getenv("DNS_SERVER"),
		DNSProtocol:         envOr("DNS_PROTOCOL", "plain"),
		AuthRetryTimeout:    envDuration("AUTH_RETRY_TIMEOUT", 5*time.Second),
		ConnectDialTimeout:  envDuration("CONNECT_DIAL_TIMEOUT", 10*time.Second),
		IdleTimeout:         envDuration("IDLE_TIMEOUT", 300*time.Second),
		HTTPTimeout:         envDuration("HTTP_TIMEOUT", 30*time.Second),
		AuthFailRateLimit:   envInt("AUTH_FAIL_RATE_LIMIT", 5),
		AuthFailWindow:      envDuration("AUTH_FAIL_WINDOW", 60*time.Second),
		AdminLoginRateLimit: envInt("ADMIN_LOGIN_RATE_LIMIT", 5),
		AdminLoginWindow:    envDuration("ADMIN_LOGIN_WINDOW", 15*time.Minute),
		AdminLoginGlobalMax: envInt("ADMIN_LOGIN_GLOBAL_MAX", 100),
		TrustedProxyCIDRs:   envCSV("TRUSTED_PROXY_CIDRS", nil),
		UserPortMin:         envInt("USER_PORT_MIN", 8081),
		UserPortMax:         envInt("USER_PORT_MAX", 8090),
		LogFormat:           envOr("LOG_FORMAT", "human"),
		LogHeaders:          envBool("LOG_HEADERS", false),
		LogNetMode:          os.Getenv("LOG_NET_MODE"),
		LogNetAddr:          os.Getenv("LOG_NET_ADDR"),
		LogNetBatchSize:     envInt("LOG_NET_BATCH_SIZE", 100),
		LogNetFlushInterval: envDuration("LOG_NET_FLUSH_INTERVAL", 5*time.Second),
		PACEnabled:          envBool("PAC_ENABLED", false),
		PACPath:             envOr("PAC_PATH", "/proxy.pac"),
		PACProxyEndpoint:    os.Getenv("PAC_PROXY_ENDPOINT"),
		PACBypassDomains: envCSV("PAC_BYPASS_DOMAINS",
			[]string{"venmo.com", "paypal.com", "paypalobjects.com", "braintreegateway.com", "braintree-api.com"}),
		PProfEnabled: envBool("PPROF_ENABLED", false),
		PProfListen:  envOr("PPROF_LISTEN", "127.0.0.1:6060"),
		DemoMode:     envBool("DEMO_MODE", false),
	}

	// Built-in autocert terminates TLS in-process, so cookies are always served
	// over HTTPS — imply ForceHTTPS to get the Secure flag and HSTS.
	if cfg.AutocertHost != "" {
		cfg.ForceHTTPS = true
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.ProxyDBPath == "" {
		return fmt.Errorf("PROXY_DB_PATH must not be empty")
	}
	if c.AdminUser == "" {
		return fmt.Errorf("ADMIN_USER is required")
	}
	if c.AdminPassword == "" {
		return fmt.Errorf("ADMIN_PASSWORD is required (bcrypt hash)")
	}
	if c.LogFormat != "json" && c.LogFormat != "human" {
		return fmt.Errorf("LOG_FORMAT must be 'json' or 'human', got %q", c.LogFormat)
	}
	switch c.DNSProtocol {
	case "plain", "tls", "https":
	default:
		return fmt.Errorf("DNS_PROTOCOL must be 'plain', 'tls', or 'https', got %q", c.DNSProtocol)
	}
	if c.DNSProtocol != "plain" && c.DNSServer == "" {
		return fmt.Errorf("DNS_SERVER is required when DNS_PROTOCOL is %q", c.DNSProtocol)
	}
	if c.UserPortMin > c.UserPortMax {
		return fmt.Errorf("USER_PORT_MIN (%d) must be <= USER_PORT_MAX (%d)", c.UserPortMin, c.UserPortMax)
	}
	switch c.LogNetMode {
	case "", "json-udp", "json-http":
	default:
		return fmt.Errorf("LOG_NET_MODE must be 'json-udp', 'json-http', or empty, got %q", c.LogNetMode)
	}
	if c.LogNetMode != "" && c.LogNetAddr == "" {
		return fmt.Errorf("LOG_NET_ADDR is required when LOG_NET_MODE is %q", c.LogNetMode)
	}
	if c.PACEnabled && c.PACPath == "" {
		return fmt.Errorf("PAC_PATH must not be empty when PAC_ENABLED is true")
	}
	for _, cidr := range c.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("TRUSTED_PROXY_CIDRS entry %q is not a valid CIDR: %w", cidr, err)
		}
	}
	if c.AdminLoginRateLimit < 1 {
		return fmt.Errorf("ADMIN_LOGIN_RATE_LIMIT must be >= 1, got %d", c.AdminLoginRateLimit)
	}
	if c.AdminLoginWindow <= 0 {
		return fmt.Errorf("ADMIN_LOGIN_WINDOW must be > 0, got %v", c.AdminLoginWindow)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// envCSV parses a comma-separated env var into a trimmed, non-empty slice.
// Returns fallback when the var is unset or empty.
func envCSV(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
