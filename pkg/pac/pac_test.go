package pac

import (
	"strings"
	"testing"
)

func TestGenerateRoutesBypassDirect(t *testing.T) {
	got := Generate("proxy.example.com:17001", []string{"venmo.com", "paypal.com"}, false)

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
	got := Generate("proxy.example.com:17001", []string{"venmo.com"}, false)
	for _, bad := range []string{"@", "password", "Authorization", "Basic ", "://"} {
		if strings.Contains(got, bad) {
			t.Errorf("PAC unexpectedly contains %q (possible credential leak)\n%s", bad, got)
		}
	}
}

func TestGenerateEscapesBypassDomains(t *testing.T) {
	// A hostile bypass entry must not break out of the JS string literal.
	got := Generate("h:1", []string{`evil"; return "PROXY leak:1`}, false)
	if strings.Contains(got, `evil"; return`) {
		t.Errorf("bypass domain not escaped:\n%s", got)
	}
}

func TestGenerateSanitizesEndpoint(t *testing.T) {
	// A hostile Host header must not break out of the PROXY string.
	got := Generate(`x"; return "PROXY evil:1`, []string{"venmo.com"}, false)
	if strings.Contains(got, `return "PROXY evil:1`) {
		t.Errorf("proxy endpoint not sanitized:\n%s", got)
	}
}

// A hostile Host header must not inject a second proxy (or DIRECT) into the
// result list via a semicolon.
func TestGenerateSanitizesEndpointProxyList(t *testing.T) {
	got := Generate("h:1; DIRECT", []string{"venmo.com"}, false)
	if strings.Contains(got, "h:1; DIRECT") {
		t.Errorf("proxy endpoint allowed a result-list injection:\n%s", got)
	}
}

// Captive portals are reached before the proxy is reachable, so the PAC has to
// route the local network DIRECT without being told about it.
func TestGenerateRoutesCaptivePortalNetworksDirect(t *testing.T) {
	got := Generate("proxy.example.com:17001", nil, false)

	for _, want := range []string{
		"isPlainHostName(host)",
		`isInNet(host, "10.0.0.0", "255.0.0.0")`,
		`isInNet(host, "172.16.0.0", "255.240.0.0")`,
		`isInNet(host, "192.168.0.0", "255.255.0.0")`,
		`isInNet(host, "169.254.0.0", "255.255.0.0")`,
		`isInNet(host, "127.0.0.0", "255.0.0.0")`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("PAC missing captive-portal rule %q\n---\n%s", want, got)
		}
	}

	// The local-network rules must apply to address literals only. Resolving a
	// hostname and trusting a private answer would let any resolver decide what
	// skips the proxy. TestPACRoutingDecisions covers the behavior; this guards
	// the mechanism.
	if strings.Contains(got, "dnsResolve") {
		t.Errorf("PAC resolves hostnames to classify them:\n%s", got)
	}
	// 100.64/10 is Tailscale's range as well as CGNAT — an exit node there
	// would be a full-internet bypass.
	if strings.Contains(got, "100.64.0.0") {
		t.Errorf("PAC routes the CGNAT range DIRECT:\n%s", got)
	}
}

// The OS portal-detection probes and local-only suffixes must be present even
// when the operator configured no bypass domains at all.
func TestGenerateAlwaysIncludesBuiltinBypass(t *testing.T) {
	got := Generate("h:1", nil, false)
	for _, want := range []string{"captive.apple.com", "connectivitycheck.gstatic.com", "local", "lan"} {
		if !strings.Contains(got, `"`+want+`"`) {
			t.Errorf("PAC missing built-in bypass %q\n---\n%s", want, got)
		}
	}
}

func TestGenerateDirectFallback(t *testing.T) {
	with := Generate("h:1", nil, true)
	if !strings.Contains(with, `return "PROXY h:1; DIRECT"`) {
		t.Errorf("directFallback did not append DIRECT:\n%s", with)
	}

	without := Generate("h:1", nil, false)
	if !strings.Contains(without, `return "PROXY h:1"`) {
		t.Errorf("default result should be proxy-only:\n%s", without)
	}
}

func TestMergeBypassNormalizesAndDeduplicates(t *testing.T) {
	got := mergeBypass([]string{" Venmo.COM ", "venmo.com", ".local", "", "captive.apple.com"})

	// Configured entries come first, normalized, with no repeats.
	if want := []string{"venmo.com", "local", "captive.apple.com"}; !hasPrefixSlice(got, want) {
		t.Fatalf("mergeBypass = %v, want prefix %v", got, want)
	}
	seen := map[string]int{}
	for _, d := range got {
		seen[d]++
	}
	for d, n := range seen {
		if n > 1 {
			t.Errorf("mergeBypass duplicated %q (%d times): %v", d, n, got)
		}
	}
}

func hasPrefixSlice(got, want []string) bool {
	if len(got) < len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
