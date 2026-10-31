package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"
)

// verifyLeaf checks that cert chains to ca and is valid for name — i.e. that a
// device trusting the root would accept it without a warning.
func verifyLeaf(t *testing.T, ca *CA, cert *tls.Certificate, name string) {
	t.Helper()

	if len(cert.Certificate) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf + CA); iOS will not build the chain itself", len(cert.Certificate))
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	caCert, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		t.Fatalf("parsing chained CA: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     name,
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("leaf for %q does not verify: %v", name, err)
	}
}

func TestGetCertificateChainsToCA(t *testing.T) {
	ca := testCA(t, Options{})

	for _, sni := range []string{"example.com", "www.sub.example.co.uk", "EXAMPLE.COM."} {
		cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			t.Fatalf("GetCertificate(%q): %v", sni, err)
		}
		verifyLeaf(t, ca, cert, strings.TrimSuffix(strings.ToLower(sni), "."))
	}
}

func TestGetCertificateNoSNIFallsBackToTarget(t *testing.T) {
	ca := testCA(t, Options{})

	t.Run("hostname target", func(t *testing.T) {
		get := ca.GetCertificateFor("example.com:443")
		cert, err := get(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		verifyLeaf(t, ca, cert, "example.com")
	})

	t.Run("IP literal target gets an IP SAN", func(t *testing.T) {
		get := ca.GetCertificateFor("93.184.215.14:443")
		cert, err := get(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("93.184.215.14")) {
			t.Fatalf("IPAddresses = %v, want [93.184.215.14]", leaf.IPAddresses)
		}
		if len(leaf.DNSNames) != 0 {
			t.Errorf("DNSNames = %v, want none for an IP literal", leaf.DNSNames)
		}
	})

	t.Run("no SNI and no target", func(t *testing.T) {
		cert, err := ca.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately unverifiable: a cert error is terminal in Safari, so it
		// still blocks. Just assert we do not accidentally certify something real.
		if leaf.Subject.CommonName != noSNIHost {
			t.Fatalf("CommonName = %q, want %q", leaf.Subject.CommonName, noSNIHost)
		}
	})
}

func TestGetCertificateCachesBySNI(t *testing.T) {
	ca := testCA(t, Options{})

	first, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("second handshake for the same SNI re-minted instead of hitting the cache")
	}

	other, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Error("different SNIs shared a certificate")
	}

	hits, misses := ca.CacheStats()
	if hits != 1 || misses != 2 {
		t.Errorf("CacheStats() = (%d hits, %d misses), want (1, 2)", hits, misses)
	}
}

func TestLeafTTLHonoured(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	ca := testCA(t, Options{LeafTTL: 48 * time.Hour, Now: func() time.Time { return now }})

	cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(-time.Hour); !leaf.NotBefore.Equal(want) {
		t.Errorf("NotBefore = %v, want %v (one hour of clock-skew slack)", leaf.NotBefore, want)
	}
	if want := now.Add(48 * time.Hour); !leaf.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want %v", leaf.NotAfter, want)
	}
}

func TestAllLeavesShareOneKey(t *testing.T) {
	ca := testCA(t, Options{})

	a, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if a.PrivateKey != b.PrivateKey {
		t.Error("leaves do not share the startup key — each miss now pays a keygen")
	}
}

func TestRotateSwapsCAAndFlushesCache(t *testing.T) {
	ca := testCA(t, Options{})

	before, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	newCert, newKey := testCAMaterial(t, "evan-proxy test CA v2")
	if err := ca.Rotate(newCert, newKey); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if got := ca.Subject(); got != "evan-proxy test CA v2" {
		t.Errorf("Subject() = %q, want the rotated CA", got)
	}

	after, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("rotation served a cached leaf signed by the retired CA — the device would reject it")
	}
	verifyLeaf(t, ca, after, "example.com")
}

func TestRotateRejectsMismatchedMaterial(t *testing.T) {
	ca := testCA(t, Options{})
	certA, _ := testCAMaterial(t, "A")
	_, keyB := testCAMaterial(t, "B")

	if err := ca.Rotate(certA, keyB); err == nil {
		t.Fatal("Rotate accepted a key that does not match the certificate")
	}
	if err := ca.Rotate(nil, nil); err == nil {
		t.Fatal("Rotate accepted nil material")
	}
}

func TestNewCARejectsNonCACertificates(t *testing.T) {
	ca := testCA(t, Options{})
	cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	signer, ok := cert.PrivateKey.(cryptoSigner)
	if !ok {
		t.Fatalf("leaf private key %T does not sign", cert.PrivateKey)
	}
	if _, err := NewCA(leaf, signer, Options{}); err == nil {
		t.Fatal("NewCA accepted a leaf certificate as a CA")
	}
	if _, err := NewCA(nil, signer, Options{}); err == nil {
		t.Fatal("NewCA accepted a nil certificate")
	}
}

func TestParseCARoundTrip(t *testing.T) {
	cert, key := testCAMaterial(t, "evan-proxy round trip CA")

	ca, err := ParseCA(pemEncodeCert(t, cert), pemEncodeKey(t, key), Options{})
	if err != nil {
		t.Fatalf("ParseCA: %v", err)
	}
	if got := ca.Subject(); got != "evan-proxy round trip CA" {
		t.Errorf("Subject() = %q", got)
	}

	exported := ca.ExportPEM()
	if !strings.Contains(string(exported), "BEGIN CERTIFICATE") {
		t.Errorf("ExportPEM did not produce a PEM block:\n%s", exported)
	}
	reparsed, err := parseCertPEM(exported)
	if err != nil {
		t.Fatalf("re-parsing ExportPEM output: %v", err)
	}
	if !reparsed.Equal(cert) {
		t.Error("ExportPEM did not round-trip to the original certificate")
	}

	// ExportDER must hand out a copy — a caller mutating it would corrupt the
	// CA for every subsequent handshake.
	der := ca.ExportDER()
	der[0] ^= 0xff
	if ca.ExportDER()[0] == der[0] {
		t.Error("ExportDER returned the CA's own backing array")
	}
}

func TestParseCARejectsGarbage(t *testing.T) {
	cert, key := testCAMaterial(t, "cn")
	certPEM, keyPEM := pemEncodeCert(t, cert), pemEncodeKey(t, key)

	tests := []struct {
		name     string
		cert     []byte
		key      []byte
		wantFrag string
	}{
		{"cert not PEM", []byte("hello"), keyPEM, "not PEM-encoded"},
		{"key not PEM", certPEM, []byte("hello"), "not PEM-encoded"},
		{"cert is a key block", keyPEM, keyPEM, "expected a CERTIFICATE"},
		{"mismatched key", certPEM, pemEncodeKey(t, mustOtherKey(t)), "does not match"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCA(tc.cert, tc.key, Options{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantFrag) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantFrag)
			}
		})
	}
}

func TestLoadCAFromDisk(t *testing.T) {
	cert, key := testCAMaterial(t, "evan-proxy disk CA")
	dir := t.TempDir()
	certPath, keyPath := dir+"/ca.crt", dir+"/ca.key"
	writeFile(t, certPath, pemEncodeCert(t, cert))
	writeFile(t, keyPath, pemEncodeKey(t, key))

	ca, err := LoadCA(certPath, keyPath, Options{})
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if got := ca.Subject(); got != "evan-proxy disk CA" {
		t.Errorf("Subject() = %q", got)
	}

	if _, err := LoadCA(dir+"/missing.crt", keyPath, Options{}); err == nil {
		t.Error("LoadCA accepted a missing certificate file")
	}
}

// TestRotateDuringMintDoesNotCacheStaleLeaf covers the window where a leaf is
// being signed as the CA rotates: caching it would serve a chain the device can
// no longer validate, long after the rotation "completed".
func TestRotateDuringMintDoesNotCacheStaleLeaf(t *testing.T) {
	ca := testCA(t, Options{})

	// Mint against the current CA, then rotate before the result is cached —
	// exactly the interleaving certFor's generation check exists to catch.
	stale, gen, err := ca.mint("example.com", false)
	if err != nil {
		t.Fatal(err)
	}

	newCert, newKey := testCAMaterial(t, "evan-proxy test CA v2")
	if err := ca.Rotate(newCert, newKey); err != nil {
		t.Fatal(err)
	}

	ca.mu.RLock()
	current := ca.gen
	ca.mu.RUnlock()
	if current == gen {
		t.Fatal("Rotate did not advance the CA generation")
	}

	// The next handshake must get a leaf signed by the new CA, never the stale one.
	fresh, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if string(fresh.Certificate[1]) == string(stale.Certificate[1]) {
		t.Fatal("served a leaf chained to the retired CA")
	}
	verifyLeaf(t, ca, fresh, "example.com")
}
