package mitm

import "testing"

// TestPassthroughKeepsAppleServicesWorking is the safety test: intercepting
// push or iCloud during a block takes out iMessage and Find My, which turns a
// screen-time pause into a "we cannot reach our kid" problem.
func TestPassthroughKeepsAppleServicesWorking(t *testing.T) {
	allowed := []string{
		"apple.com",
		"www.apple.com",
		"appleid.apple.com",
		"gateway.push.apple.com",
		"1-courier.push.apple.com",
		"p45-content.icloud.com",
		"icloud.com",
		"is1-ssl.mzstatic.com",
		"gs.apple.com",
		"mesu.apple.com",
		"gdmf.apple.com",
		"configuration.apple.com",
		"xp.apple.com",
		"init.itunes.apple.com",
		"apps.apple.com",
		"cdn.cdn-apple.com",
		"static.gc.apple.com",
		"p01-content.aaplimg.com",
		// Normalisation: a CONNECT target carries a port, DNS allows a trailing
		// dot, and case is not significant.
		"APPLEID.APPLE.COM:443",
		"gateway.push.apple.com.",
		"appleid.apple.com:443",
	}
	for _, host := range allowed {
		if !Passthrough(host) {
			t.Errorf("Passthrough(%q) = false — blocking this breaks an Apple service", host)
		}
	}
}

func TestPassthroughBlocksEverythingElse(t *testing.T) {
	blocked := []string{
		"example.com",
		"youtube.com",
		"www.youtube.com",
		"",
		"   ",
		// Suffix matching must not be substring matching: an attacker-registered
		// lookalike must not slip through.
		"notapple.com",
		"evilapple.com",
		"apple.com.evil.net",
		"icloud.com.attacker.io",
		"fakeicloud.com",
	}
	for _, host := range blocked {
		if Passthrough(host) {
			t.Errorf("Passthrough(%q) = true — this host should get the block page", host)
		}
	}
}

func TestCompilePatterns(t *testing.T) {
	exact, suffixes := compilePatterns([]string{"*.example.com", "bare.example.org", "", "  "})

	if _, ok := exact["example.com"]; !ok {
		t.Error("a *.example.com wildcard should also match the bare example.com")
	}
	if _, ok := exact["bare.example.org"]; !ok {
		t.Error("bare pattern missing from the exact set")
	}
	if len(suffixes) != 1 || suffixes[0] != ".example.com" {
		t.Errorf("suffixes = %v, want [.example.com]", suffixes)
	}
	if len(exact) != 2 {
		t.Errorf("exact = %v, want exactly two entries (empty patterns dropped)", exact)
	}
}
