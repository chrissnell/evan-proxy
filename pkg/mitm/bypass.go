package mitm

import "strings"

// applePatterns is Apple's standard "must not be intercepted" set — software
// update, push, iCloud, App Store, carrier bundles. Intercepting any of them
// breaks iMessage and Find My for the duration of a block, which turns a
// screen-time pause into a safety problem.
//
// Phase 1 hardcodes this list so the proof of concept cannot ship without it.
// Phase 2 replaces Passthrough with the SQLite-backed pkg/allowlist seeded from
// exactly these patterns, and this file goes away.
var applePatterns = []string{
	"*.apple.com",
	"*.icloud.com",
	"*.push.apple.com",
	"*.mzstatic.com",
	"*.gc.apple.com",
	"*.cdn-apple.com",
	"*.itunes.apple.com",
	"*.apps.apple.com",
	"*.aaplimg.com",
	"mesu.apple.com",
	"gs.apple.com",
	"xp.apple.com",
	"configuration.apple.com",
	"gdmf.apple.com",
}

// exactHosts and wildcardSuffixes are applePatterns split at init into the two
// shapes Passthrough actually matches against.
var exactHosts, wildcardSuffixes = compilePatterns(applePatterns)

// compilePatterns splits patterns into an exact-match set and a list of
// leading-dot suffixes. A "*.example.com" pattern matches both
// "anything.example.com" and the bare "example.com".
func compilePatterns(patterns []string) (map[string]struct{}, []string) {
	exact := make(map[string]struct{}, len(patterns))
	var suffixes []string

	for _, p := range patterns {
		p = normalizeHost(p)
		switch {
		case p == "":
		case strings.HasPrefix(p, "*."):
			base := strings.TrimPrefix(p, "*.")
			suffixes = append(suffixes, "."+base)
			exact[base] = struct{}{}
		default:
			exact[p] = struct{}{}
		}
	}
	return exact, suffixes
}

// Passthrough reports whether a blocked user's CONNECT to host should tunnel
// normally instead of getting the block page.
func Passthrough(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if _, ok := exactHosts[h]; ok {
		return true
	}
	for _, suffix := range wildcardSuffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}
