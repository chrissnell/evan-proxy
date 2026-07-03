package pac

import (
	"strings"
	"testing"
)

func TestGenerateRoutesBypassDirect(t *testing.T) {
	got := Generate("proxy.example.com:17001", []string{"venmo.com", "paypal.com"})

	for _, want := range []string{
		`dnsDomainIs(host, "." + bypass[i])`,
		`return "DIRECT"`,
		`return "PROXY proxy.example.com:17001"`,
		`"venmo.com"`,
		`"paypal.com"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("PAC missing %q\n---\n%s", want, got)
		}
	}
}

// The PAC must never carry credentials — this guards the security property the
// endpoint is built on.
func TestGenerateContainsNoCredentials(t *testing.T) {
	got := Generate("proxy.example.com:17001", []string{"venmo.com"})
	for _, bad := range []string{"@", "password", "Authorization", "Basic ", "://"} {
		if strings.Contains(got, bad) {
			t.Errorf("PAC unexpectedly contains %q (possible credential leak)\n%s", bad, got)
		}
	}
}

func TestGenerateEscapesBypassDomains(t *testing.T) {
	// A hostile bypass entry must not break out of the JS string literal.
	got := Generate("h:1", []string{`evil"; return "PROXY leak:1`})
	if strings.Contains(got, `evil"; return`) {
		t.Errorf("bypass domain not escaped:\n%s", got)
	}
}

func TestGenerateSanitizesEndpoint(t *testing.T) {
	// A hostile Host header must not break out of the PROXY string.
	got := Generate(`x"; return "PROXY evil:1`, []string{"venmo.com"})
	if strings.Contains(got, `return "PROXY evil:1`) {
		t.Errorf("proxy endpoint not sanitized:\n%s", got)
	}
}
