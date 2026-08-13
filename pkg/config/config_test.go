package config

import (
	"os"
	"testing"
	"time"
)

func setEnv(t *testing.T, pairs map[string]string) {
	t.Helper()
	for k, v := range pairs {
		t.Setenv(k, v)
	}
}

func validEnv() map[string]string {
	return map[string]string{
		"PROXY_USERS_FILE": "/tmp/users.json",
		"ADMIN_USER":       "admin",
		"ADMIN_PASSWORD":   "$2a$10$test",
	}
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t, validEnv())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AdminListen != ":9090" {
		t.Errorf("AdminListen = %q, want :9090", cfg.AdminListen)
	}
	if cfg.LogFormat != "human" {
		t.Errorf("LogFormat = %q, want human", cfg.LogFormat)
	}
	if cfg.AuthRetryTimeout != 5*time.Second {
		t.Errorf("AuthRetryTimeout = %v, want 5s", cfg.AuthRetryTimeout)
	}
	if cfg.UserPortMin != 8081 {
		t.Errorf("UserPortMin = %d, want 8081", cfg.UserPortMin)
	}
	if cfg.UserPortMax != 8090 {
		t.Errorf("UserPortMax = %d, want 8090", cfg.UserPortMax)
	}
}

func TestLoadMissingAdminUser(t *testing.T) {
	setEnv(t, map[string]string{
		"PROXY_USERS_FILE": "/tmp/users.json",
		"ADMIN_PASSWORD":   "$2a$10$test",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing ADMIN_USER")
	}
}

func TestLoadMissingAdminPassword(t *testing.T) {
	setEnv(t, map[string]string{
		"PROXY_USERS_FILE": "/tmp/users.json",
		"ADMIN_USER":       "admin",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing ADMIN_PASSWORD")
	}
}

func TestLoadInvalidLogFormat(t *testing.T) {
	env := validEnv()
	env["LOG_FORMAT"] = "xml"
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid LOG_FORMAT")
	}
}

func TestLoadCustomValues(t *testing.T) {
	env := validEnv()
	env["DNS_SERVER"] = "1.1.1.1:53"
	env["AUTH_FAIL_RATE_LIMIT"] = "10"
	env["AUTH_FAIL_WINDOW"] = "120s"
	setEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DNSServer != "1.1.1.1:53" {
		t.Errorf("DNSServer = %q, want 1.1.1.1:53", cfg.DNSServer)
	}
	if cfg.AuthFailRateLimit != 10 {
		t.Errorf("AuthFailRateLimit = %d, want 10", cfg.AuthFailRateLimit)
	}
	if cfg.AuthFailWindow != 120*time.Second {
		t.Errorf("AuthFailWindow = %v, want 120s", cfg.AuthFailWindow)
	}
}

func TestLoadDNSProtocolDefault(t *testing.T) {
	setEnv(t, validEnv())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DNSProtocol != "plain" {
		t.Errorf("DNSProtocol = %q, want plain", cfg.DNSProtocol)
	}
}

func TestLoadDNSProtocolInvalid(t *testing.T) {
	env := validEnv()
	env["DNS_PROTOCOL"] = "quic"
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid DNS_PROTOCOL")
	}
}

func TestLoadDNSProtocolTLSRequiresServer(t *testing.T) {
	env := validEnv()
	env["DNS_PROTOCOL"] = "tls"
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for DNS_PROTOCOL=tls without DNS_SERVER")
	}
}

func TestLoadDNSProtocolHTTPSRequiresServer(t *testing.T) {
	env := validEnv()
	env["DNS_PROTOCOL"] = "https"
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for DNS_PROTOCOL=https without DNS_SERVER")
	}
}

func TestLoadDNSProtocolTLSWithServer(t *testing.T) {
	env := validEnv()
	env["DNS_PROTOCOL"] = "tls"
	env["DNS_SERVER"] = "1.1.1.1:853"
	setEnv(t, env)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DNSProtocol != "tls" {
		t.Errorf("DNSProtocol = %q, want tls", cfg.DNSProtocol)
	}
}

func TestLoadAdminLoginDefaults(t *testing.T) {
	setEnv(t, validEnv())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AdminLoginRateLimit != 5 {
		t.Errorf("AdminLoginRateLimit = %d, want 5", cfg.AdminLoginRateLimit)
	}
	if cfg.AdminLoginWindow != 15*time.Minute {
		t.Errorf("AdminLoginWindow = %v, want 15m", cfg.AdminLoginWindow)
	}
	if cfg.AdminLoginGlobalMax != 100 {
		t.Errorf("AdminLoginGlobalMax = %d, want 100", cfg.AdminLoginGlobalMax)
	}
	if len(cfg.TrustedProxyCIDRs) != 0 {
		t.Errorf("TrustedProxyCIDRs = %v, want empty", cfg.TrustedProxyCIDRs)
	}
}

func TestLoadValidTrustedProxyCIDR(t *testing.T) {
	env := validEnv()
	env["TRUSTED_PROXY_CIDRS"] = "10.0.0.0/8, 192.168.0.0/16"
	setEnv(t, env)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("want 2 CIDRs, got %v", cfg.TrustedProxyCIDRs)
	}
}

func TestLoadInvalidTrustedProxyCIDR(t *testing.T) {
	env := validEnv()
	env["TRUSTED_PROXY_CIDRS"] = "not-a-cidr"
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestLoadInvalidAdminLoginRateLimit(t *testing.T) {
	env := validEnv()
	env["ADMIN_LOGIN_RATE_LIMIT"] = "0"
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("expected error for ADMIN_LOGIN_RATE_LIMIT=0 (would lock out admin)")
	}
}

func TestLoadInvalidAdminLoginWindow(t *testing.T) {
	env := validEnv()
	env["ADMIN_LOGIN_WINDOW"] = "0s"
	setEnv(t, env)
	if _, err := Load(); err == nil {
		t.Fatal("expected error for ADMIN_LOGIN_WINDOW=0 (would panic time.NewTicker)")
	}
}

// Suppress unused import warning
var _ = os.Getenv
