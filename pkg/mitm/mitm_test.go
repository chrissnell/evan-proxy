package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testCA mints an ephemeral root CA for use in tests.
func testCA(t *testing.T, opts Options) *CA {
	t.Helper()
	cert, key := testCAMaterial(t, "evan-proxy test CA")
	ca, err := NewCA(cert, key, opts)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

func testCAMaterial(t *testing.T, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("signing CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	return cert, key
}

func pemEncodeCert(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func pemEncodeKey(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected key type %T", key)
	}
	der, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
