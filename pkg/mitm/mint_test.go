package mitm

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestLeafTemplateGolden pins every field of the leaf template.
//
// The template is the part of this package iOS judges. A silent change to a key
// usage, a validity window or a SAN shape is the kind of drift that only shows
// up as "Safari says the certificate is invalid" on a device nobody has handy,
// so it gets a golden file rather than spot assertions.
func TestLeafTemplateGolden(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	serial, _ := new(big.Int).SetString("0123456789abcdef0123456789abcdef", 16)

	cases := []struct {
		name   string
		host   string
		isIP   bool
		golden string
	}{
		{"hostname", "example.com", false, "leaf_hostname.golden"},
		{"ip literal", "93.184.215.14", true, "leaf_ip.golden"},
		{"no sni", noSNIHost, false, "leaf_nosni.golden"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := leafTemplate(tc.host, tc.isIP, serial, now, DefaultLeafTTL)
			got := describeTemplate(tmpl)
			path := filepath.Join("testdata", tc.golden)

			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run `go test ./pkg/mitm -update` to create it)", err)
			}
			if got != string(want) {
				t.Errorf("leaf template drifted.\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

// describeTemplate renders the fields iOS validates, in a stable order.
func describeTemplate(tmpl *x509Certificate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SerialNumber: %x\n", tmpl.SerialNumber)
	fmt.Fprintf(&b, "CommonName: %s\n", tmpl.Subject.CommonName)
	fmt.Fprintf(&b, "NotBefore: %s\n", tmpl.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "NotAfter: %s\n", tmpl.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "KeyUsage: %d\n", tmpl.KeyUsage)
	fmt.Fprintf(&b, "ExtKeyUsage: %v\n", tmpl.ExtKeyUsage)
	fmt.Fprintf(&b, "DNSNames: %v\n", tmpl.DNSNames)
	fmt.Fprintf(&b, "IPAddresses: %v\n", tmpl.IPAddresses)
	fmt.Fprintf(&b, "IsCA: %t\n", tmpl.IsCA)
	fmt.Fprintf(&b, "BasicConstraintsValid: %t\n", tmpl.BasicConstraintsValid)
	return b.String()
}

func TestLeafIdentity(t *testing.T) {
	tests := []struct {
		sni      string
		target   string
		wantName string
		wantIP   bool
	}{
		{"example.com", "example.com:443", "example.com", false},
		{"EXAMPLE.COM", "", "example.com", false},
		{"example.com.", "", "example.com", false},
		{"  example.com  ", "", "example.com", false},
		{"", "example.com:443", "example.com", false},
		{"", "example.com", "example.com", false},
		{"", "93.184.215.14:443", "93.184.215.14", true},
		{"", "[2606:2800:21f:cb07::]:443", "2606:2800:21f:cb07::", true},
		{"", "", noSNIHost, false},
		{"", "   ", noSNIHost, false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("sni=%q target=%q", tc.sni, tc.target), func(t *testing.T) {
			name, isIP := leafIdentity(tc.sni, tc.target)
			if name != tc.wantName || isIP != tc.wantIP {
				t.Errorf("leafIdentity = (%q, %t), want (%q, %t)", name, isIP, tc.wantName, tc.wantIP)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"Example.COM":      "example.com",
		"example.com.":     "example.com",
		"example.com:443":  "example.com",
		"[::1]:443":        "::1",
		"[::1]":            "::1",
		"":                 "",
		"  ":               "",
		"*.apple.com":      "*.apple.com",
		"WWW.Apple.Com.:8": "www.apple.com",
	}
	for in, want := range tests {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// A leaf cached for a hot hostname must be re-minted once it nears expiry. The
// cache is bounded by count, not age, so without that check a pod alive longer
// than LeafTTL serves an expired certificate and Safari shows a cert warning
// instead of the block page.
func TestCertForRemintsExpiringLeaf(t *testing.T) {
	now := time.Now()
	ca := testCA(t, Options{LeafTTL: time.Hour, Now: func() time.Time { return now }})

	first, err := ca.certFor("example.com", "")
	if err != nil {
		t.Fatalf("first certFor: %v", err)
	}

	// Still fresh: the same cached leaf comes back.
	now = now.Add(30 * time.Minute)
	cached, err := ca.certFor("example.com", "")
	if err != nil {
		t.Fatalf("cached certFor: %v", err)
	}
	if cached.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Error("re-minted a leaf that was still fresh")
	}

	// Past expiry: a new leaf, valid at the current clock.
	now = now.Add(time.Hour)
	renewed, err := ca.certFor("example.com", "")
	if err != nil {
		t.Fatalf("renewed certFor: %v", err)
	}
	if renewed.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("served the expired leaf from cache instead of re-minting")
	}
	if !now.Before(renewed.Leaf.NotAfter) {
		t.Errorf("renewed leaf already expired: NotAfter=%s, now=%s", renewed.Leaf.NotAfter, now)
	}
	if renewed.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("renewed leaf DNS name = %q, want example.com", renewed.Leaf.DNSNames[0])
	}
}
