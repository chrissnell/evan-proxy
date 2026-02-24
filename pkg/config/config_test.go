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

	if cfg.ListenPlain != ":8080" {
		t.Errorf("ListenPlain = %q, want :8080", cfg.ListenPlain)
	}
	if cfg.ListenTLS != ":443" {
		t.Errorf("ListenTLS = %q, want :443", cfg.ListenTLS)
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

func TestLoadTLSMismatch(t *testing.T) {
	env := validEnv()
	env["TLS_CERT"] = "/tmp/cert.pem"
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for TLS_CERT without TLS_KEY")
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
	env["LISTEN_PLAIN"] = ":9999"
	env["DNS_SERVER"] = "1.1.1.1:53"
	env["AUTH_FAIL_RATE_LIMIT"] = "10"
	env["AUTH_FAIL_WINDOW"] = "120s"
	setEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenPlain != ":9999" {
		t.Errorf("ListenPlain = %q, want :9999", cfg.ListenPlain)
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

// Suppress unused import warning
var _ = os.Getenv
