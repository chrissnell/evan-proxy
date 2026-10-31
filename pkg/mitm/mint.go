package mitm

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	// noSNIHost names the certificate handed to a client that sent no SNI and
	// whose CONNECT target is unusable. It fails validation on purpose — a cert
	// error is terminal in Safari, so it still blocks.
	noSNIHost = "no-sni.invalid"

	// leafBackdate absorbs client clock skew: a device a few minutes fast must
	// not see a not-yet-valid certificate.
	leafBackdate = time.Hour

	// leafRenewBefore retires a cached leaf this long before it expires. The
	// cache is bounded by count, not age, so a hot entry would otherwise be
	// served past its own NotAfter once the pod outlives LeafTTL — and an
	// expired certificate means a Safari cert warning instead of the block
	// page. The margin also stops a leaf expiring mid-page-load.
	leafRenewBefore = time.Minute
)

// certFor returns a leaf for this handshake, minting one on a cache miss.
//
// sni is the ClientHello server name ("" if absent) and target is the CONNECT
// request's host (with or without a port, "" if unknown).
func (c *CA) certFor(sni, target string) (*tls.Certificate, error) {
	name, isIP := leafIdentity(sni, target)
	if cert, ok := c.cache.get(name); ok && c.leafFresh(cert) {
		return cert, nil
	}

	cert, gen, err := c.mint(name, isIP)
	if err != nil {
		return nil, err
	}

	// Drop the leaf rather than cache it if the CA rotated while we were
	// signing: the device can no longer validate a chain to the retired root.
	c.mu.RLock()
	current := c.gen
	c.mu.RUnlock()
	if current == gen {
		c.cache.put(name, cert)
	}
	return cert, nil
}

// leafFresh reports whether a cached leaf has enough validity left to serve.
func (c *CA) leafFresh(cert *tls.Certificate) bool {
	return cert.Leaf != nil && c.opts.Now().Add(leafRenewBefore).Before(cert.Leaf.NotAfter)
}

// leafIdentity resolves the name a leaf must certify, preferring the SNI the
// client asked for and falling back to the CONNECT target. An IP literal needs
// an IP SAN rather than a DNS SAN, so the caller is told which it got.
func leafIdentity(sni, target string) (name string, isIP bool) {
	if h := normalizeHost(sni); h != "" {
		// SNI is never an IP literal in a conforming ClientHello, but a
		// non-conforming client that sends one still needs an IP SAN.
		return h, net.ParseIP(h) != nil
	}
	if h := normalizeHost(target); h != "" {
		return h, net.ParseIP(h) != nil
	}
	return noSNIHost, false
}

// normalizeHost lowercases a host, strips any port and the root-label trailing
// dot, and unwraps a bracketed IPv6 literal.
func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

// mint signs a fresh leaf for name and reports the CA generation it signed
// against, so the caller can tell whether a concurrent rotation invalidated it.
func (c *CA) mint(name string, isIP bool) (*tls.Certificate, uint64, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, 0, fmt.Errorf("mitm: generating serial: %w", err)
	}

	c.mu.RLock()
	caCert, caKey, gen := c.cert, c.key, c.gen
	c.mu.RUnlock()

	now, ttl := c.opts.Now(), c.opts.LeafTTL
	tmpl := leafTemplate(name, isIP, serial, now, ttl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, c.leafKey.Public(), caKey)
	if err != nil {
		return nil, 0, fmt.Errorf("mitm: signing leaf for %q: %w", name, err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der, caCert.Raw},
		PrivateKey:  c.leafKey,
		Leaf:        tmpl,
	}, gen, nil
}

// leafTemplate builds the leaf certificate template. Deliberately minimal: the
// fewer extensions it carries, the less there is for a future iOS release to
// object to. Split out from mint so the golden-file test can assert on it
// directly and catch drift.
func leafTemplate(name string, isIP bool, serial *big.Int, now time.Time, ttl time.Duration) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-leafBackdate),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if isIP {
		tmpl.IPAddresses = []net.IP{net.ParseIP(name)}
	} else {
		tmpl.DNSNames = []string{name}
	}
	return tmpl
}
