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
// never heard of: bare hostnames ("wifi", "logon"), local-only DNS suffixes
// (.local, .lan), and private-range address literals (the gateway a portal
// redirects to).
//
// Those rules are deliberately narrow. Resolving an arbitrary hostname and
// routing it DIRECT because the answer looks private would hand the filtering
// decision to whatever resolver the device is talking to: a hostile network —
// or a public wildcard DNS service like nip.io — could point any name at a LAN
// address and escape the proxy. Only an address literal is trusted. Local
// destinations reached that way are still unfiltered and unlogged, so anything
// running on the LAN is reachable off-proxy; that is the price of a portal
// login working at all.
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

// privateNets are the address ranges a captive portal's gateway lives in.
// 100.64.0.0/10 (CGNAT) is deliberately absent: it is also Tailscale's range,
// so an exit node there would be a ready-made full-internet bypass, and portal
// gateways overwhelmingly sit in 10/8 anyway.
var privateNets = [][2]string{
	{"10.0.0.0", "255.0.0.0"},
	{"172.16.0.0", "255.240.0.0"},
	{"192.168.0.0", "255.255.0.0"},
	{"169.254.0.0", "255.255.0.0"}, // link-local
	{"127.0.0.0", "255.0.0.0"},     // the device itself; never reachable via a remote proxy
}

// Generate renders a PAC file that routes the bypass domain suffixes, the
// built-in captive-portal set, and local-network destinations DIRECT, and
// everything else through proxyEndpoint ("host:port"). See the package doc for
// why the local-network rules are limited to address literals.
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
	b.WriteString("  // An IPv6 literal has no dot either, so exclude it explicitly.\n")
	b.WriteString("  if (host.indexOf(\":\") === -1 && isPlainHostName(host)) {\n")
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
	b.WriteString("  // Portals redirect to the gateway by address. Only an address literal\n")
	b.WriteString("  // is trusted: resolving a hostname and trusting a private answer would\n")
	b.WriteString("  // let any network point any name at the LAN and escape the proxy.\n")
	b.WriteString("  if (/^[0-9]+(\\.[0-9]+){3}$/.test(host)) {\n")
	for _, n := range privateNets {
		b.WriteString(fmt.Sprintf("    if (isInNet(host, %s, %s)) { return \"DIRECT\"; }\n",
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

// jsRaw strips characters from a value that is embedded in a PAC result string
// (the proxy endpoint, which comes from the request Host header). jsString
// already handles quoting, so the load-bearing character here is ";" — it
// separates entries in a PAC result list and would otherwise let a hostile
// Host inject a second proxy, or DIRECT.
func jsRaw(s string) string {
	return strings.NewReplacer("\"", "", "\n", "", "\r", "", "\\", "", ";", "").Replace(s)
}

// jsString renders s as a safe double-quoted JavaScript string literal. U+2028
// and U+2029 are stripped too: Go accepts them in a Host header, and older
// JavaScript engines treat them as line terminators inside a literal.
func jsString(s string) string {
	r := strings.NewReplacer(
		"\\", "\\\\", "\"", "\\\"", "\n", "", "\r", "", "\u2028", "", "\u2029", "")
	return "\"" + r.Replace(s) + "\""
}
