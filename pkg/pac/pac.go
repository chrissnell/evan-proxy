// Package pac generates proxy auto-config (PAC) files.
//
// A PAC lets an iOS "Auto" Global HTTP Proxy route most traffic through
// evan-proxy while sending a configurable set of domains DIRECT (bypassing the
// proxy entirely). This is the supported way to exclude specific sites — e.g.
// apps whose login flow breaks when routed through the proxy — because iOS's
// Manual global-proxy payload has no bypass list.
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

// Generate renders a PAC file that routes the bypass domain suffixes DIRECT and
// everything else through proxyEndpoint ("host:port"). The output contains no
// credentials.
func Generate(proxyEndpoint string, bypass []string) string {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase();\n")
	b.WriteString("  var bypass = [")
	for i, d := range bypass {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(jsString(strings.ToLower(strings.TrimSpace(d))))
	}
	b.WriteString("];\n")
	b.WriteString("  for (var i = 0; i < bypass.length; i++) {\n")
	b.WriteString("    if (host === bypass[i] || dnsDomainIs(host, \".\" + bypass[i])) {\n")
	b.WriteString("      return \"DIRECT\";\n")
	b.WriteString("    }\n")
	b.WriteString("  }\n")
	b.WriteString(fmt.Sprintf("  return \"PROXY %s\";\n", jsRaw(proxyEndpoint)))
	b.WriteString("}\n")
	return b.String()
}

// jsRaw sanitizes a value interpolated into the PAC without quotes (the proxy
// endpoint), stripping characters that could break the surrounding literal.
func jsRaw(s string) string {
	return strings.NewReplacer("\"", "", "\n", "", "\r", "", "\\", "").Replace(s)
}

// jsString renders s as a safe double-quoted JavaScript string literal.
func jsString(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "", "\r", "")
	return "\"" + r.Replace(s) + "\""
}
