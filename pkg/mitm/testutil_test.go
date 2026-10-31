package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"testing"
)

// cryptoSigner is an alias used by tests that assert NewCA's input validation.
type cryptoSigner = crypto.Signer

func mustOtherKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// x509Certificate aliases the template type so the golden helper's signature
// stays readable.
type x509Certificate = x509.Certificate
