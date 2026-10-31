package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubBlockPage records the hosts handed to it and writes a recognisable body,
// standing in for pkg/mitm so the connect-path tests exercise routing rather
// than TLS.
type stubBlockPage struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (s *stubBlockPage) ServeBlockPage(conn net.Conn, host, user string) error {
	s.mu.Lock()
	s.calls = append(s.calls, host+"|"+user)
	s.mu.Unlock()

	if s.err != nil {
		return s.err
	}
	_, err := conn.Write([]byte("STUB-BLOCK-PAGE"))
	return err
}

func (s *stubBlockPage) served() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// connectAsBlockedUser runs a CONNECT for an authenticated user whose traffic
// is paused, and returns the proxy's first response line plus whatever followed.
func connectAsBlockedUser(t *testing.T, h *Handler, target string) (statusLine, rest string) {
	t.Helper()

	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		target, target, basicAuth("alice", "secret"))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading status line: %v", err)
	}
	// Drain the response headers up to the blank line so what follows on the
	// socket is tunnel payload.
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading headers: %v", err)
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}

	// Whatever the proxy sends next is the tunnel body. Nothing at all is a
	// valid outcome (an established passthrough tunnel is silent), so a short
	// deadline rather than a read to EOF.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := br.Read(buf)
	return strings.TrimSpace(line), string(buf[:n])
}

// setupBlockedProxy returns a handler whose only user, alice, is in downtime.
func setupBlockedProxy(t *testing.T) (*Handler, *stubBlockPage) {
	t.Helper()

	h := setupProxy(t)
	db := h.users.(interface {
		SetDowntimeUntil(string, time.Time) error
	})
	if err := db.SetDowntimeUntil("alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	stub := &stubBlockPage{}
	h.cfg.MITMEnabled = true
	h.SetMITM(stub)
	return h, stub
}

// TestBlockedUserGetsBlockPageNotAFailure is the core of the design: a paused
// user's CONNECT must *succeed*. Every failure shape we shipped before — closed
// listener, FIN, RST, 403, TLS alert — made iOS Safari retry DIRECT with PAC
// fallback on, so the block did not block.
func TestBlockedUserGetsBlockPageNotAFailure(t *testing.T) {
	h, stub := setupBlockedProxy(t)

	status, rest := connectAsBlockedUser(t, h, "example.com:443")

	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("status = %q, want 200 Connection Established", status)
	}
	if !strings.Contains(rest, "STUB-BLOCK-PAGE") {
		t.Errorf("block page was not served on the tunnel, got %q", rest)
	}
	if got := stub.served(); len(got) != 1 || got[0] != "example.com:443|alice" {
		t.Errorf("ServeBlockPage calls = %v, want one for example.com:443 as alice", got)
	}
}

// TestBlockedUserPassesThroughAppleHosts covers the safety carve-out: iMessage
// and Find My must keep working while a kid's internet is paused.
func TestBlockedUserPassesThroughAppleHosts(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	h, stub := setupBlockedProxy(t)

	// Passthrough matches on hostname, so keep the Apple name and redirect the
	// dial at the local test server.
	rec := &dialRecorder{addr: strings.TrimPrefix(target.URL, "http://")}
	h.dial = rec.dial

	status, _ := connectAsBlockedUser(t, h, "gateway.push.apple.com:443")

	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("status = %q, want the tunnel to be established", status)
	}
	if got := stub.served(); len(got) != 0 {
		t.Errorf("Apple host was intercepted: %v", got)
	}
	if got := rec.dialed(); got != "gateway.push.apple.com:443" {
		t.Errorf("dialed %q, want a real tunnel to gateway.push.apple.com:443", got)
	}
}

// TestBlockedUserFallsBackTo403WithoutMITM keeps today's behaviour intact when
// the feature flag is off.
func TestBlockedUserFallsBackTo403WithoutMITM(t *testing.T) {
	h, stub := setupBlockedProxy(t)
	h.cfg.MITMEnabled = false

	status, _ := connectAsBlockedUser(t, h, "example.com:443")

	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("status = %q, want 403 when MITM is disabled", status)
	}
	if got := stub.served(); len(got) != 0 {
		t.Errorf("block page served with MITM off: %v", got)
	}
}

// TestBlockedUserFallsBackTo403WithoutAServer covers MITM_ENABLED with no CA
// wired in — misconfiguration must not hang the connection.
func TestBlockedUserFallsBackTo403WithoutAServer(t *testing.T) {
	h, _ := setupBlockedProxy(t)
	h.SetMITM(nil)

	status, _ := connectAsBlockedUser(t, h, "example.com:443")

	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("status = %q, want 403 when no block-page server is configured", status)
	}
}

func TestDisabledUserIsBlockedOnlyUnderMITM(t *testing.T) {
	h, stub := setupBlockedProxy(t)

	db := h.users.(interface {
		SetDowntimeUntil(string, time.Time) error
		SetEnabled(string, bool) error
	})
	// Clear downtime so "disabled" is the only reason left.
	if err := db.SetDowntimeUntil("alice", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetEnabled("alice", false); err != nil {
		t.Fatal(err)
	}

	if reason := h.blockReason("alice"); reason != "disabled" {
		t.Errorf("blockReason with MITM on = %q, want \"disabled\"", reason)
	}

	h.cfg.MITMEnabled = false
	if reason := h.blockReason("alice"); reason != "" {
		t.Errorf("blockReason with MITM off = %q, want \"\" (the closed port is the block)", reason)
	}
	_ = stub
}

// TestListenerStaysBoundDuringBlockUnderMITM: closing the port is exactly the
// failure shape Safari falls back from, so with MITM on it must stay bound.
func TestListenerStaysBoundDuringBlockUnderMITM(t *testing.T) {
	h := setupProxy(t)
	db := h.users.(interface {
		SetEnabled(string, bool) error
	})
	if err := db.SetEnabled("alice", false); err != nil {
		t.Fatal(err)
	}

	if h.listenerWanted("alice") {
		t.Error("disabled user keeps a listener with MITM off — the port close is the block there")
	}

	h.cfg.MITMEnabled = true
	if !h.listenerWanted("alice") {
		t.Error("disabled user lost their listener with MITM on — Safari would fall back DIRECT")
	}
}

// dialRecorder captures the address a tunnel was opened for and connects to a
// fixed test server instead.
type dialRecorder struct {
	addr string
	mu   sync.Mutex
	got  string
}

func (d *dialRecorder) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.got = address
	d.mu.Unlock()
	return net.Dial(network, d.addr)
}

func (d *dialRecorder) dialed() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.got
}
