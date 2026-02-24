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

	// Optional JSON users file for initial seeding
	ProxyUsersFile string

	// Listeners
	ListenPlain string
	ListenTLS   string
	AdminListen string

	// TLS
	TLSCert string
	TLSKey  string

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

	// Logging
	LogFormat string // "json" or "human"
}

func Load() (*Config, error) {
	cfg := &Config{
		ProxyDBPath:        envOr("PROXY_DB_PATH", "/data/evan-proxy/users.db"),
		ProxyUsersFile:     os.Getenv("PROXY_USERS_FILE"),
		ListenPlain:        envOr("LISTEN_PLAIN", ":8080"),
		ListenTLS:          envOr("LISTEN_TLS", ":443"),
		AdminListen:        envOr("ADMIN_LISTEN", ":9090"),
		TLSCert:            os.Getenv("TLS_CERT"),
		TLSKey:             os.Getenv("TLS_KEY"),
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
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("TLS_CERT and TLS_KEY must both be set or both empty")
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
