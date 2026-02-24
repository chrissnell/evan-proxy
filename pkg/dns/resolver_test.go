package dns

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNewPlainDefault(t *testing.T) {
	r, err := New("plain", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.NetResolver() == nil {
		t.Fatal("expected non-nil NetResolver for plain")
	}
	if r.doh != nil {
		t.Fatal("expected nil doh client for plain")
	}
}

func TestNewPlainCustom(t *testing.T) {
	r, err := New("plain", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.NetResolver() == nil {
		t.Fatal("expected non-nil NetResolver")
	}
}

func TestNewTLS(t *testing.T) {
	r, err := New("tls", "1.1.1.1:853")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.NetResolver() == nil {
		t.Fatal("expected non-nil NetResolver for tls")
	}
}

func TestNewTLSDefaultPort(t *testing.T) {
	r, err := New("tls", "1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.NetResolver() == nil {
		t.Fatal("expected non-nil NetResolver for tls")
	}
}

func TestNewDoHMissingURL(t *testing.T) {
	_, err := New("https", "")
	if err == nil {
		t.Fatal("expected error for empty DoH URL")
	}
}

func TestNewDoH(t *testing.T) {
	r, err := New("https", "https://1.1.1.1/dns-query")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.NetResolver() != nil {
		t.Fatal("expected nil NetResolver for DoH")
	}
	if r.doh == nil {
		t.Fatal("expected non-nil doh client")
	}
}

func TestNewInvalidProtocol(t *testing.T) {
	_, err := New("quic", "1.1.1.1")
	if err == nil {
		t.Fatal("expected error for invalid protocol")
	}
}

func TestGetOrCreateCaches(t *testing.T) {
	// Reset cache for test.
	cacheMu.Lock()
	cache = map[string]*Resolver{}
	cacheMu.Unlock()

	r1, err := GetOrCreate("plain", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r2, err := GetOrCreate("plain", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r1 != r2 {
		t.Fatal("expected same resolver instance from cache")
	}
}

// buildDNSResponse creates a minimal DNS wire-format response for testing.
func buildDNSResponse(name string, ip net.IP) []byte {
	n, _ := dnsmessage.NewName(name)
	var answers []dnsmessage.Resource

	if ip4 := ip.To4(); ip4 != nil {
		var a [4]byte
		copy(a[:], ip4)
		answers = append(answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  n,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   300,
			},
			Body: &dnsmessage.AResource{A: a},
		})
	} else {
		var aaaa [16]byte
		copy(aaaa[:], ip.To16())
		answers = append(answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  n,
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
				TTL:   300,
			},
			Body: &dnsmessage.AAAAResource{AAAA: aaaa},
		})
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:           true,
			RecursionDesired:   true,
			RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  n,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
		Answers: answers,
	}
	packed, _ := msg.Pack()
	return packed
}

func TestDoHLookup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buildDNSResponse("example.com.", net.ParseIP("93.184.216.34")))
	}))
	defer ts.Close()

	resolver, err := New("https", ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	addrs, err := resolver.LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup error: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected at least one address")
	}

	found := false
	for _, a := range addrs {
		if a.IP.Equal(net.ParseIP("93.184.216.34")) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 93.184.216.34 in results, got %v", addrs)
	}
}

func TestDoHServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	resolver, err := New("https", ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = resolver.LookupIPAddr(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestDoHMalformedResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write([]byte("not valid dns"))
	}))
	defer ts.Close()

	resolver, err := New("https", ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = resolver.LookupIPAddr(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error for malformed response")
	}
}

func TestDoHEmptyResponse(t *testing.T) {
	// Return valid DNS with no answers — should return empty, no error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := dnsmessage.NewName("example.com.")
		msg := dnsmessage.Message{
			Header: dnsmessage.Header{Response: true, RecursionDesired: true},
			Questions: []dnsmessage.Question{{
				Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
			}},
		}
		packed, _ := msg.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
	defer ts.Close()

	resolver, err := New("https", ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	addrs, err := resolver.LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 0 {
		t.Errorf("expected 0 addrs for empty response, got %d", len(addrs))
	}
}

func TestDoHAAAAResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buildDNSResponse("example.com.", net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")))
	}))
	defer ts.Close()

	resolver, err := New("https", ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	addrs, err := resolver.LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup error: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected at least one AAAA address")
	}
}

func TestDoHCancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow response — context should cancel first.
		<-r.Context().Done()
	}))
	defer ts.Close()

	resolver, err := New("https", ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = resolver.LookupIPAddr(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestNewEmptyProtocol(t *testing.T) {
	// Empty protocol should behave like "plain".
	r, err := New("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.NetResolver() == nil {
		t.Fatal("expected non-nil NetResolver for empty protocol")
	}
}

func TestGetOrCreateError(t *testing.T) {
	_, err := GetOrCreate("invalid", "x")
	if err == nil {
		t.Fatal("expected error for invalid protocol")
	}
}

func TestPlainResolverLookupReal(t *testing.T) {
	// Use system default resolver to look up a real domain.
	r, err := New("plain", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	addrs, err := r.LookupIPAddr(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("lookup error: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected at least one address for localhost")
	}
}
