// Package mitm terminates TLS on a hijacked CONNECT and serves an HTTPS block
// page signed by a device-trusted root CA.
//
// It exists because iOS Safari, with ProxyPACFallbackAllowed=true, silently
// retries DIRECT on every proxy *failure* shape — closed listener, FIN, RST,
// 403, TLS fatal alert — so a disabled user simply browses around the proxy.
// Succeeding the connection on our own terms is the only shape Safari accepts
// as final. See .context/mitm-design.md.
package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"
)

// Options configures leaf minting and the certificate cache.
type Options struct {
	// LeafTTL is how long a minted leaf stays valid. Zero uses DefaultLeafTTL.
	LeafTTL time.Duration
	// CacheSize bounds the minted-leaf LRU by entry count. Zero uses
	// DefaultCacheSize.
	CacheSize int
	// Now overrides the clock. Tests only; zero value uses time.Now.
	Now func() time.Time
}

const (
	// DefaultLeafTTL matches the design's 7-day leaf lifetime: long enough that
	// a cached cert outlives any browsing session, short enough that a leaked
	// leaf expires on its own.
	DefaultLeafTTL = 7 * 24 * time.Hour
	// DefaultCacheSize bounds the leaf LRU. A blocked device touches a few
	// hundred hosts at most before the kid gives up.
	DefaultCacheSize = 1000
)

func (o Options) withDefaults() Options {
	if o.LeafTTL <= 0 {
		o.LeafTTL = DefaultLeafTTL
	}
	if o.CacheSize <= 0 {
		o.CacheSize = DefaultCacheSize
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// CA signs per-SNI leaf certificates for the block page.
//
// All forged leaves share one ephemeral private key generated at startup —
// standard practice (mitmproxy, squid-ssl-bump) because iOS validates the chain,
// not SPKI uniqueness, and it keeps a cache miss to a single ECDSA signature.
type CA struct {
	// mu guards the CA material. Read on every cache miss, written only by
	// Rotate.
	mu      sync.RWMutex
	cert    *x509.Certificate
	certDER []byte
	key     crypto.Signer

	// gen increments on every Rotate so a leaf minted against the retired CA
	// cannot land in the cache after the purge.
	gen uint64

	leafKey crypto.Signer
	cache   *certCache
	opts    Options
}

// NewCA returns a CA signing with key, which must be cert's private key.
func NewCA(cert *x509.Certificate, key crypto.Signer, opts Options) (*CA, error) {
	if cert == nil {
		return nil, fmt.Errorf("mitm: nil CA certificate")
	}
	if key == nil {
		return nil, fmt.Errorf("mitm: nil CA key")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("mitm: certificate %q is not a CA (basicConstraints cA=false)", cert.Subject.CommonName)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("mitm: certificate %q lacks the certSign key usage", cert.Subject.CommonName)
	}
	if !publicKeysEqual(key.Public(), cert.PublicKey) {
		return nil, fmt.Errorf("mitm: CA key does not match certificate %q", cert.Subject.CommonName)
	}

	// Leaf keys are ECDSA P-256 regardless of the CA's own algorithm: fast to
	// generate, fast to sign with, and universally accepted by Apple clients.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm: generating shared leaf key: %w", err)
	}

	opts = opts.withDefaults()
	return &CA{
		cert:    cert,
		certDER: cert.Raw,
		key:     key,
		leafKey: leafKey,
		cache:   newCertCache(opts.CacheSize),
		opts:    opts,
	}, nil
}

// LoadCA reads a PEM-encoded certificate and private key from disk. The key may
// be SEC 1 (EC PRIVATE KEY), PKCS#8, or PKCS#1.
func LoadCA(certPath, keyPath string, opts Options) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: reading CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: reading CA key: %w", err)
	}
	return ParseCA(certPEM, keyPEM, opts)
}

// ParseCA builds a CA from PEM blocks.
func ParseCA(certPEM, keyPEM []byte, opts Options) (*CA, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return NewCA(cert, key, opts)
}

func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("mitm: CA certificate is not PEM-encoded")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("mitm: expected a CERTIFICATE PEM block, got %q", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parsing CA certificate: %w", err)
	}
	return cert, nil
}

func parseKeyPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("mitm: CA key is not PEM-encoded")
	}

	var (
		parsed any
		err    error
	)
	switch block.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("mitm: unsupported private key PEM block %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("mitm: parsing CA key: %w", err)
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("mitm: CA key of type %T cannot sign", parsed)
	}
	return signer, nil
}

// publicKeysEqual reports whether two public keys are the same key.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}

// GetCertificate is the tls.Config callback. The stdlib TLS server hands us the
// ClientHello — SNI included — so there is no separate "read the ClientHello
// ourselves" step once the hijacked conn is wrapped in tls.Server.
//
// A client that sent no SNI gets a certificate for noSNIHost, which fails
// validation and therefore still blocks. Use GetCertificateFor when the CONNECT
// target is known: it is a better fallback and renders the page.
func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.certFor(hello.ServerName, "")
}

// GetCertificateFor returns a tls.Config callback that falls back to the
// CONNECT target host when the client sends no SNI.
func (c *CA) GetCertificateFor(target string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.certFor(hello.ServerName, target)
	}
}

// Rotate swaps in fresh CA material and flushes the leaf cache. Leaves signed
// by the retired CA would fail validation on the device, so they must not be
// served after the swap.
func (c *CA) Rotate(cert *x509.Certificate, key crypto.Signer) error {
	if cert == nil || key == nil {
		return fmt.Errorf("mitm: rotate requires both a certificate and a key")
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("mitm: rotate: certificate %q is not a signing CA", cert.Subject.CommonName)
	}
	if !publicKeysEqual(key.Public(), cert.PublicKey) {
		return fmt.Errorf("mitm: rotate: key does not match certificate %q", cert.Subject.CommonName)
	}

	c.mu.Lock()
	c.cert = cert
	c.certDER = cert.Raw
	c.key = key
	c.gen++
	c.mu.Unlock()

	c.cache.purge()
	return nil
}

// ExportPEM returns the CA certificate as PEM, for the admin UI download and
// the mobileconfig payload.
func (c *CA) ExportPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ExportDER()})
}

// ExportDER returns the raw DER of the CA certificate.
func (c *CA) ExportDER() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]byte, len(c.certDER))
	copy(out, c.certDER)
	return out
}

// Subject returns the CA's common name, for startup logging.
func (c *CA) Subject() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert.Subject.CommonName
}

// CacheStats returns lifetime leaf-cache hit and miss counts.
func (c *CA) CacheStats() (hits, misses uint64) {
	return c.cache.stats()
}
