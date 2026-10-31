package mitm

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ServerOptions tunes the hijacked-connection lifecycle.
type ServerOptions struct {
	// HandshakeTimeout bounds the forged TLS handshake. Zero uses 10s.
	HandshakeTimeout time.Duration
	// IdleTimeout bounds how long we wait for the next request on a kept-alive
	// block-page connection. Zero uses 30s.
	IdleTimeout time.Duration
	// MaxRequests caps requests served per hijacked connection, so a client
	// that loops on the page cannot pin the connection open forever. Zero uses 32.
	MaxRequests int
	// Now overrides the clock. Tests only; zero value uses time.Now.
	Now func() time.Time
}

func (o ServerOptions) withDefaults() ServerOptions {
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 30 * time.Second
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = 32
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Server terminates TLS on a hijacked CONNECT and serves the block page.
type Server struct {
	ca   *CA
	opts ServerOptions
}

// NewServer returns a Server signing forged leaves with ca.
func NewServer(ca *CA, opts ServerOptions) *Server {
	return &Server{ca: ca, opts: opts.withDefaults()}
}

// CA returns the signing CA, for the admin API's cert export.
func (s *Server) CA() *CA { return s.ca }

// ServeBlockPage completes a TLS handshake as host on an already-established
// CONNECT tunnel and answers every request with the block page.
//
// The caller must have written "200 Connection Established" already: the client
// has to believe it is talking to the destination before it will send a
// ClientHello. conn is left open for the caller to close.
func (s *Server) ServeBlockPage(conn net.Conn, host, user string) error {
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: s.ca.GetCertificateFor(host),
		MinVersion:     tls.VersionTLS12,
	})

	if err := conn.SetDeadline(s.opts.Now().Add(s.opts.HandshakeTimeout)); err != nil {
		return fmt.Errorf("mitm %s/%s: setting handshake deadline: %w", user, host, err)
	}
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("mitm %s/%s: tls handshake: %w", user, host, err)
	}
	defer tlsConn.Close()

	if err := s.serve(tlsConn, host); err != nil {
		return fmt.Errorf("mitm %s/%s: %w", user, host, err)
	}
	return nil
}

// serve answers requests on the established TLS connection until the client
// goes away, the idle timeout fires, or MaxRequests is reached.
//
// A hand-rolled loop rather than http.Server.Serve: we already own a single
// connection, and a one-shot net.Listener wrapper would hand the connection's
// lifetime to a goroutine we would then have to wait on anyway.
func (s *Server) serve(conn net.Conn, host string) error {
	br := bufio.NewReader(conn)

	for i := 0; i < s.opts.MaxRequests; i++ {
		if err := conn.SetDeadline(s.opts.Now().Add(s.opts.IdleTimeout)); err != nil {
			return fmt.Errorf("setting request deadline: %w", err)
		}

		req, err := http.ReadRequest(br)
		if err != nil {
			// The client hanging up after reading the page is the normal exit.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			var netErr net.Error
			if i > 0 && errors.As(err, &netErr) && netErr.Timeout() {
				return nil // served at least one page, then went idle
			}
			return fmt.Errorf("reading request: %w", err)
		}

		// Drain any body so the next request starts at a framed boundary.
		_, _ = io.Copy(io.Discard, req.Body)
		req.Body.Close()

		keepAlive := i < s.opts.MaxRequests-1 && req.ProtoAtLeast(1, 1) &&
			!hasToken(req.Header.Get("Connection"), "close")

		if err := s.writeResponse(conn, req, host, keepAlive); err != nil {
			return err
		}
		if !keepAlive {
			return nil
		}
	}
	return nil
}

// writeResponse renders the block page and writes it to conn as an HTTP/1.1
// response.
func (s *Server) writeResponse(conn net.Conn, req *http.Request, host string, keepAlive bool) error {
	resp := newBlockPageResponse(req, host, s.opts.Now(), keepAlive)
	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("writing block page: %w", err)
	}
	return nil
}

// hasToken reports whether a comma-separated header value contains token,
// case-insensitively.
func hasToken(header, token string) bool {
	for _, v := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(v), token) {
			return true
		}
	}
	return false
}
