// Package pac generates proxy auto-config (PAC) files.
//
// A PAC lets an iOS "Auto" Global HTTP Proxy route most traffic through
// evan-proxy while sending a configurable set of domains DIRECT (bypassing the
// proxy entirely). This is the supported way to exclude specific sites — e.g.
// apps whose login flow breaks when routed through the proxy — because iOS's
// Manual global-proxy payload has no bypass list.
//
// CAPTIVE PORTALS: a portal network blocks everything until you log in, so the
// portal page itself must never be routed through the proxy — the proxy is
// unreachable at that point. Three rules cover portals the bypass list has
// never heard of: bare hostnames (http://wifi, http://logon), local-only DNS
// suffixes (.local, .lan), and hosts that resolve into a private, link-local,
// or CGNAT range (the gateway address a portal redirects to, including via DNS
// hijack). None of those addresses can reach the public internet, so routing
// them DIRECT costs no filtering coverage.
//
// SECURITY: a PAC file contains ONLY routing rules — hostnames and the proxy
// host:port. It never contains credentials. Proxy authentication is unchanged:
// iOS still sends the Basic proxy password (from the MDM profile) directly to
// the proxy on the 407 challenge. Nothing here is secret, so the PAC is served
// unauthenticated.
package pac

import (
	"fmt"
	"strings"
)

// ContentType is the MIME type browsers/OSes expect for a PAC file.
const ContentType = "application/x-ns-proxy-autoconfig"

// builtinBypass is always routed DIRECT, on top of the configured bypass list.
// It holds the OS captive-portal detection endpoints every platform probes
// before it will declare a network usable, plus the DNS suffixes that only ever
// name a machine on the local network. A portal login is impossible if these go
// through an unreachable proxy, so they are not left to configuration.
var builtinBypass = []string{
	// Local-only DNS suffixes — never the public internet.
	"local",
	"lan",
	"home",
	"internal",
	"localdomain",
	// OS captive-portal detection probes.
	"captive.apple.com",
	"connectivitycheck.gstatic.com",
	"connectivitycheck.android.com",
	"clients3.google.com",
	"msftconnecttest.com",
	"msftncsi.com",
	"detectportal.firefox.com",
	"network-test.debian.org",
	"nmcheck.gnome.org",
	"neverssl.com",
}

// privateNets are the address ranges a captive portal's gateway lives in. A
// host resolving into one of these is on the local network by definition.
var privateNets = [][2]string{
	{"10.0.0.0", "255.0.0.0"},
	{"172.16.0.0", "255.240.0.0"},
	{"192.168.0.0", "255.255.0.0"},
	{"169.254.0.0", "255.255.0.0"}, // link-local
	{"100.64.0.0", "255.192.0.0"},  // CGNAT, common on in-flight/hotel Wi-Fi
	{"127.0.0.0", "255.0.0.0"},
}

// Generate renders a PAC file that routes the bypass domain suffixes, the
// built-in captive-portal set, and local-network destinations DIRECT, and
// everything else through proxyEndpoint ("host:port").
//
// When directFallback is true the proxy result carries a trailing "; DIRECT",
// so a client that cannot reach the proxy connects directly instead of failing.
// That keeps a captive-portal login working off a cached PAC, but it also means
// traffic silently goes unfiltered whenever the proxy is unreachable — so it is
// opt-in.
//
// The output contains no credentials.
func Generate(proxyEndpoint string, bypass []string, directFallback bool) string {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase();\n")
	b.WriteString("  var i;\n")
	b.WriteString("\n")
	b.WriteString("  // A captive portal is often reached by bare hostname, e.g. just \"wifi\".\n")
	b.WriteString("  if (isPlainHostName(host)) {\n")
	b.WriteString("    return \"DIRECT\";\n")
	b.WriteString("  }\n")
	b.WriteString("\n")
	b.WriteString("  var bypass = [")
	for i, d := range mergeBypass(bypass) {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(jsString(d))
	}
	b.WriteString("];\n")
	b.WriteString("  for (i = 0; i < bypass.length; i++) {\n")
	b.WriteString("    if (host === bypass[i] || dnsDomainIs(host, \".\" + bypass[i])) {\n")
	b.WriteString("      return \"DIRECT\";\n")
	b.WriteString("    }\n")
	b.WriteString("  }\n")
	b.WriteString("\n")
	b.WriteString("  // Portals redirect to the gateway's private address, sometimes by\n")
	b.WriteString("  // hijacking DNS. Those addresses cannot reach the public internet.\n")
	b.WriteString("  var ip = dnsResolve(host);\n")
	b.WriteString("  if (ip) {\n")
	for _, n := range privateNets {
		b.WriteString(fmt.Sprintf("    if (isInNet(ip, %s, %s)) { return \"DIRECT\"; }\n",
			jsString(n[0]), jsString(n[1])))
	}
	b.WriteString("  }\n")
	b.WriteString("\n")
	result := fmt.Sprintf("PROXY %s", jsRaw(proxyEndpoint))
	if directFallback {
		result += "; DIRECT"
	}
	b.WriteString(fmt.Sprintf("  return %s;\n", jsString(result)))
	b.WriteString("}\n")
	return b.String()
}

// mergeBypass normalizes the configured bypass list, appends the built-in
// captive-portal entries, and drops blanks and duplicates. Order is stable:
// configured entries first, then built-ins.
func mergeBypass(bypass []string) []string {
	seen := make(map[string]struct{}, len(bypass)+len(builtinBypass))
	out := make([]string, 0, len(bypass)+len(builtinBypass))
	for _, d := range append(append([]string{}, bypass...), builtinBypass...) {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// jsRaw sanitizes a value interpolated into a PAC string literal (the proxy
// endpoint), stripping characters that could break out of the literal.
func jsRaw(s string) string {
	return strings.NewReplacer("\"", "", "\n", "", "\r", "", "\\", "", ";", "").Replace(s)
}

// jsString renders s as a safe double-quoted JavaScript string literal.
func jsString(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "", "\r", "")
	return "\"" + r.Replace(s) + "\""
}
