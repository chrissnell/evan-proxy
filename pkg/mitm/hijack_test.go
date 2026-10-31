package mitm

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// dialBlockPage runs ServeBlockPage over an in-memory pipe and hands back a
// real crypto/tls client connected to it, exactly as iOS would be after the
// proxy answers its CONNECT with 200.
func dialBlockPage(t *testing.T, ca *CA, srv *Server, host, sni string) (*tls.Conn, <-chan error) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })

	errCh := make(chan error, 1)
	go func() {
		defer server.Close()
		errCh <- srv.ServeBlockPage(server, host, "evan")
	}()

	roots := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(ca.ExportDER())
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(caCert)

	tlsClient := tls.Client(client, &tls.Config{ServerName: sni, RootCAs: roots})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake against the forged cert failed: %v", err)
	}
	return tlsClient, errCh
}

// TestServeBlockPageEndToEnd is the regression test for the whole premise: a
// client that trusts our root must see a *successful* HTTPS exchange with the
// destination. Every shape we shipped before this — closed listener, FIN, RST,
// 403, TLS fatal alert — looked like a proxy failure and made Safari retry
// DIRECT. If this test ever starts failing, blocking is broken on the device.
func TestServeBlockPageEndToEnd(t *testing.T) {
	ca := testCA(t, Options{})
	srv := NewServer(ca, ServerOptions{})

	conn, errCh := dialBlockPage(t, ca, srv, "example.com:443", "example.com")

	// The handshake already proved the cert validates for example.com.
	if got := conn.ConnectionState().ServerName; got != "example.com" {
		t.Errorf("negotiated ServerName = %q", got)
	}
	if v := conn.ConnectionState().Version; v < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version 0x%04x, want >= TLS 1.2", v)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("Connection", "close")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Pancho says no.") {
		t.Errorf("response is not the block page:\n%s", truncate(string(body)))
	}
	if !strings.Contains(string(body), "example.com") {
		t.Error("block page does not name the destination host")
	}

	drainClient(conn)
	if err := <-errCh; err != nil {
		t.Errorf("ServeBlockPage returned %v", err)
	}
}

func TestServeBlockPageKeepsConnectionAlive(t *testing.T) {
	ca := testCA(t, Options{})
	srv := NewServer(ca, ServerOptions{})

	conn, errCh := dialBlockPage(t, ca, srv, "example.com:443", "example.com")
	br := bufio.NewReader(conn)

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/favicon.ico", nil)
		if err := req.Write(conn); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("response %d: status %d", i, resp.StatusCode)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatalf("draining response %d: %v", i, err)
		}
		resp.Body.Close()
	}

	conn.Close()
	if err := <-errCh; err != nil {
		t.Errorf("ServeBlockPage returned %v", err)
	}
}

// TestServeBlockPageStopsAtMaxRequests guards against a client pinning the
// hijacked connection open forever.
func TestServeBlockPageStopsAtMaxRequests(t *testing.T) {
	ca := testCA(t, Options{})
	srv := NewServer(ca, ServerOptions{MaxRequests: 2})

	conn, errCh := dialBlockPage(t, ca, srv, "example.com:443", "example.com")
	br := bufio.NewReader(conn)

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		if err := req.Write(conn); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		if i == 1 && !resp.Close {
			t.Error("last allowed response was not marked Connection: close")
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	drainClient(conn)
	if err := <-errCh; err != nil {
		t.Errorf("ServeBlockPage returned %v", err)
	}
}

func TestServeBlockPageHandlesPOSTWithBody(t *testing.T) {
	ca := testCA(t, Options{})
	srv := NewServer(ca, ServerOptions{})

	conn, errCh := dialBlockPage(t, ca, srv, "example.com:443", "example.com")
	br := bufio.NewReader(conn)

	req, _ := http.NewRequest(http.MethodPost, "https://example.com/submit", strings.NewReader("a=1&b=2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// The body must have been drained, so a second request still frames.
	req2, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req2.Header.Set("Connection", "close")
	if err := req2.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.ReadResponse(br, req2)
	if err != nil {
		t.Fatalf("second request did not frame after a POST body: %v", err)
	}
	// net.Pipe is synchronous: leaving the body unread would block the server
	// mid-write until its deadline fires.
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	drainClient(conn)
	if err := <-errCh; err != nil {
		t.Errorf("ServeBlockPage returned %v", err)
	}
}

// TestServeBlockPageUntrustedClientStillBlocks covers the device that never got
// the CA: the handshake fails, which Safari treats as terminal, so the user is
// still blocked. The proxy must report it rather than hang.
func TestServeBlockPageUntrustedClientStillBlocks(t *testing.T) {
	ca := testCA(t, Options{})
	srv := NewServer(ca, ServerOptions{})

	client, server := net.Pipe()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		defer server.Close()
		errCh <- srv.ServeBlockPage(server, "example.com:443", "evan")
	}()

	// No RootCAs: the client does not trust our forged leaf.
	tlsClient := tls.Client(client, &tls.Config{ServerName: "example.com"})
	if err := tlsClient.Handshake(); err == nil {
		t.Fatal("client without the CA accepted the forged certificate")
	}

	err := <-errCh
	if err == nil {
		t.Fatal("ServeBlockPage reported success for a rejected handshake")
	}
	if !strings.Contains(err.Error(), "example.com") || !strings.Contains(err.Error(), "evan") {
		t.Errorf("error %q does not name the user and host for the log line", err)
	}
}

func TestServeBlockPageHandshakeTimeout(t *testing.T) {
	ca := testCA(t, Options{})
	srv := NewServer(ca, ServerOptions{HandshakeTimeout: 50 * time.Millisecond})

	client, server := net.Pipe()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		defer server.Close()
		errCh <- srv.ServeBlockPage(server, "example.com:443", "evan")
	}()

	// Client connects but never sends a ClientHello.
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("silent client was reported as served")
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Errorf("error = %v, want a timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeBlockPage did not time out on a silent client")
	}
}

func TestServerExposesCA(t *testing.T) {
	ca := testCA(t, Options{})
	if got := NewServer(ca, ServerOptions{}).CA(); got != ca {
		t.Error("Server.CA() did not return the configured CA")
	}
}

// drainClient consumes whatever the server sends next, in particular the TLS
// close_notify. net.Pipe is unbuffered, so without a reader crypto/tls blocks
// on its own five-second close deadline; a real socket's send buffer absorbs it.
func drainClient(conn net.Conn) {
	go io.Copy(io.Discard, conn)
}

func truncate(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
