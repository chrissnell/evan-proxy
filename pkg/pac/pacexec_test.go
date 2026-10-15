package pac

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The PAC is JavaScript evaluated by CFNetwork on the device, so string
// assertions over the generated source cannot tell a working rule from a
// syntax error or an inverted comparison — and with ProxyPACFallbackAllowed
// set (required for captive-portal logins), a PAC the device cannot evaluate
// means it browses unfiltered. These tests run the real thing against the
// reference PAC helper functions and assert the routing decision.
//
// Skipped when node is unavailable.

// pacShim implements the PAC helper functions FindProxyForURL may call, with a
// stubbed resolver, then prints one decision per line of input.
const pacShim = `
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const dns = JSON.parse(process.argv[3]);

const toOctets = s => s.split('.').map(Number);
const env = {
  isPlainHostName: h => h.indexOf('.') === -1,
  // Reference semantics: host matches if it ends with domain.
  dnsDomainIs: (h, d) => h.length >= d.length && h.slice(-d.length) === d,
  dnsResolve: h => (/^[0-9]+(\.[0-9]+){3}$/.test(h) ? h : (dns[h] || null)),
  isInNet: (host, net, mask) => {
    const ip = env.dnsResolve(host);
    if (!ip) return false;
    const [a, b, m] = [toOctets(ip), toOctets(net), toOctets(mask)];
    return a.every((o, i) => (o & m[i]) === (b[i] & m[i]));
  },
  shExpMatch: (s, p) =>
    new RegExp('^' + p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$').test(s),
};

const keys = Object.keys(env);
const find = new Function(...keys, src + '; return FindProxyForURL;')(...keys.map(k => env[k]));
for (const host of process.argv.slice(4)) {
  console.log(find('http://' + host + '/', host));
}
`

// evalPAC runs the generated PAC under node and returns FindProxyForURL's
// result for each host.
func evalPAC(t *testing.T, pacSrc string, dnsJSON string, hosts ...string) []string {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available; skipping PAC execution test")
	}

	dir := t.TempDir()
	pacFile := filepath.Join(dir, "proxy.pac")
	shimFile := filepath.Join(dir, "shim.js")
	if err := os.WriteFile(pacFile, []byte(pacSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shimFile, []byte(pacShim), 0o600); err != nil {
		t.Fatal(err)
	}

	args := append([]string{shimFile, pacFile, dnsJSON}, hosts...)
	out, err := exec.Command(node, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed (PAC is not valid JavaScript?): %v\n%s\n---\n%s", err, out, pacSrc)
	}

	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(got) != len(hosts) {
		t.Fatalf("got %d decisions for %d hosts:\n%s", len(got), len(hosts), out)
	}
	return got
}

func TestPACRoutingDecisions(t *testing.T) {
	const proxy = "PROXY proxy.example.com:17001"
	src := Generate("proxy.example.com:17001", []string{"deltawifi.com", "venmo.com"}, false)

	// A hostile network — or a public wildcard DNS service like nip.io — can
	// point any name at a private address. The resolver must not get to decide
	// what skips the proxy.
	dns := `{
		"192-168-1-50.nip.io": "192.168.1.50",
		"deltawifi.com": "10.101.0.1",
		"reddit.com": "151.101.1.140"
	}`

	cases := []struct {
		host string
		want string
	}{
		// Captive portals.
		{"wifi", "DIRECT"},
		{"logon", "DIRECT"},
		{"printer.local", "DIRECT"},
		{"gateway.lan", "DIRECT"},
		{"captive.apple.com", "DIRECT"},
		{"192.168.1.1", "DIRECT"},
		{"10.101.0.1", "DIRECT"},
		{"172.19.0.1", "DIRECT"},
		{"169.254.1.1", "DIRECT"},

		// Configured bypass, including subdomains.
		{"deltawifi.com", "DIRECT"},
		{"www.deltawifi.com", "DIRECT"},
		{"venmo.com", "DIRECT"},

		// Ordinary browsing stays on the proxy.
		{"reddit.com", proxy},
		{"notresolvable.example", proxy},
		{"8.8.8.8", proxy},
		{"172.32.0.1", proxy}, // just outside 172.16/12

		// Must not be mistaken for a bypass entry.
		{"evil-neverssl.com", proxy},
		{"notdeltawifi.com", proxy},

		// A public name pointed at the LAN is a filter bypass, not a portal.
		{"192-168-1-50.nip.io", proxy},

		// An IPv6 literal has no dot, so isPlainHostName() alone would call it
		// a bare hostname and route the whole address family DIRECT.
		{"2607:f8b0:4005:80b::200e", proxy},
		{"[::1]", proxy},
	}

	hosts := make([]string, len(cases))
	for i, c := range cases {
		hosts[i] = c.host
	}

	got := evalPAC(t, src, dns, hosts...)
	for i, c := range cases {
		if got[i] != c.want {
			t.Errorf("FindProxyForURL(%q) = %q, want %q", c.host, got[i], c.want)
		}
	}
}

func TestPACDirectFallbackEvaluates(t *testing.T) {
	src := Generate("proxy.example.com:17001", nil, true)
	got := evalPAC(t, src, `{}`, "reddit.com")
	if want := "PROXY proxy.example.com:17001; DIRECT"; got[0] != want {
		t.Errorf("FindProxyForURL(reddit.com) = %q, want %q", got[0], want)
	}
}

// A hostile Host header must not be able to add a proxy to the result list or
// break out of the string literal — assert on the evaluated result, not the
// generated source.
func TestPACHostileEndpointEvaluates(t *testing.T) {
	src := Generate(`evil:1; DIRECT`, nil, false)
	got := evalPAC(t, src, `{}`, "reddit.com")
	if strings.Contains(got[0], ";") {
		t.Errorf("hostile endpoint produced a proxy list: %q", got[0])
	}
}
