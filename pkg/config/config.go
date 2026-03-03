package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Proxy user database (SQLite)
	ProxyDBPath string

	// Admin listener
	AdminListen string

	// Admin credentials
	AdminUser     string
	AdminPassword string // bcrypt hash

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

	// Per-user dedicated proxy ports
	UserPortMin int // first port in range (inclusive)
	UserPortMax int // last port in range (inclusive)

	// Logging — console
	LogFormat string // "json" or "human"

	// Logging — network (optional, independent of console)
	LogNetMode          string        // "json-udp" or "json-http", empty = disabled
	LogNetAddr          string        // UDP: "host:port", HTTP: "http://host:port/path"
	LogNetBatchSize     int           // json-http only: max entries before flush
	LogNetFlushInterval time.Duration // json-http only: max time between flushes
}

func Load() (*Config, error) {
	cfg := &Config{
		ProxyDBPath:        envOr("PROXY_DB_PATH", "/data/evan-proxy/users.db"),
		AdminListen:        envOr("ADMIN_LISTEN", ":9090"),
		AdminUser:          os.Getenv("ADMIN_USER"),
		AdminPassword:      os.Getenv("ADMIN_PASSWORD"),
		DNSServer:          os.Getenv("DNS_SERVER"),
		DNSProtocol:        envOr("DNS_PROTOCOL", "plain"),
		AuthRetryTimeout:   envDuration("AUTH_RETRY_TIMEOUT", 5*time.Second),
		ConnectDialTimeout: envDuration("CONNECT_DIAL_TIMEOUT", 10*time.Second),
		IdleTimeout:        envDuration("IDLE_TIMEOUT", 300*time.Second),
		HTTPTimeout:        envDuration("HTTP_TIMEOUT", 30*time.Second),
		AuthFailRateLimit:  envInt("AUTH_FAIL_RATE_LIMIT", 5),
		AuthFailWindow:     envDuration("AUTH_FAIL_WINDOW", 60*time.Second),
		UserPortMin:        envInt("USER_PORT_MIN", 8081),
		UserPortMax:        envInt("USER_PORT_MAX", 8090),
		LogFormat:          envOr("LOG_FORMAT", "human"),
		LogNetMode:          os.Getenv("LOG_NET_MODE"),
		LogNetAddr:          os.Getenv("LOG_NET_ADDR"),
		LogNetBatchSize:     envInt("LOG_NET_BATCH_SIZE", 100),
		LogNetFlushInterval: envDuration("LOG_NET_FLUSH_INTERVAL", 5*time.Second),
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
