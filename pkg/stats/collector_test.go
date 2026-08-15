package stats

import (
	"testing"
	"time"

	"evan-proxy/pkg/logging"
)

func TestTopHosts(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	now := time.Now()
	c.Observe(logging.Entry{Timestamp: now, Host: "a.com:443", Status: 200})
	c.Observe(logging.Entry{Timestamp: now, Host: "a.com:443", Status: 200})
	c.Observe(logging.Entry{Timestamp: now, Host: "b.com:443", Status: 200})

	top := c.TopHosts(10)
	if len(top) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(top))
	}
	if top[0].Host != "a.com" || top[0].Count != 2 {
		t.Errorf("expected a.com:2, got %s:%d", top[0].Host, top[0].Count)
	}
	if top[1].Host != "b.com" || top[1].Count != 1 {
		t.Errorf("expected b.com:1, got %s:%d", top[1].Host, top[1].Count)
	}
}

func TestTopHostsExcludesErrors(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	now := time.Now()
	c.Observe(logging.Entry{Timestamp: now, Host: "good.com:443", Status: 200})
	c.Observe(logging.Entry{Timestamp: now, Host: "bad.com:443", Status: 407})

	top := c.TopHosts(10)
	if len(top) != 1 || top[0].Host != "good.com" {
		t.Errorf("expected only good.com, got %v", top)
	}
}

func TestTopBlocked(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	now := time.Now()
	c.Observe(logging.Entry{Timestamp: now, Host: "ads.com:443", Event: "dns-block", Status: 523})
	c.Observe(logging.Entry{Timestamp: now, Host: "ads.com:443", Event: "dns-block", Status: 523})
	c.Observe(logging.Entry{Timestamp: now, Host: "tracker.com:80", Event: "dns-block", Status: 523})

	top := c.TopBlocked(10)
	if len(top) != 2 {
		t.Fatalf("expected 2 blocked hosts, got %d", len(top))
	}
	if top[0].Host != "ads.com" || top[0].Count != 2 {
		t.Errorf("expected ads.com:2, got %s:%d", top[0].Host, top[0].Count)
	}
}

func TestTrafficBuckets(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	now := time.Now()
	c.Observe(logging.Entry{Timestamp: now, Host: "a.com:443", Status: 200, BytesRead: 100, BytesWritten: 200})
	c.Observe(logging.Entry{Timestamp: now, Host: "b.com:443", Status: 200, BytesRead: 50, BytesWritten: 75})

	traffic := c.Traffic(60)
	if len(traffic) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(traffic))
	}
	if traffic[0].Requests != 2 {
		t.Errorf("expected 2 requests, got %d", traffic[0].Requests)
	}
	if traffic[0].BytesRead != 150 {
		t.Errorf("expected 150 bytes read, got %d", traffic[0].BytesRead)
	}
}

func TestSubscribe(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	ch := c.Subscribe()
	defer c.Unsubscribe(ch)

	now := time.Now()
	c.Observe(logging.Entry{Timestamp: now, Host: "a.com:443", Status: 200})

	select {
	case e := <-ch:
		if e.Host != "a.com:443" {
			t.Errorf("expected a.com:443, got %s", e.Host)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for entry")
	}
}

func TestCompact(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now()
	c.Observe(logging.Entry{Timestamp: old, Host: "old.com:443", Status: 200})
	c.Observe(logging.Entry{Timestamp: recent, Host: "new.com:443", Status: 200})

	c.compact()

	top := c.TopHosts(10)
	if len(top) != 1 || top[0].Host != "new.com" {
		t.Errorf("expected only new.com after compact, got %v", top)
	}
}

func TestHostOnly(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"example.com:443", "example.com"},
		{"example.com:80", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:443", "::1"},
	}
	for _, tt := range tests {
		got := hostOnly(tt.in)
		if got != tt.want {
			t.Errorf("hostOnly(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTopN(t *testing.T) {
	counts := map[string]int{"a": 5, "b": 3, "c": 10, "d": 1}
	top := topN(counts, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2, got %d", len(top))
	}
	if top[0].Host != "c" || top[1].Host != "a" {
		t.Errorf("expected [c, a], got [%s, %s]", top[0].Host, top[1].Host)
	}
}

// TestTraffic_EmptyIsNonNil guards the JSON shape: an idle collector must yield
// a non-nil (empty) slice so it marshals to [] not null — the iOS app's
// generated OpenAPI decoder rejects null for the non-nullable traffic array.
func TestTraffic_EmptyIsNonNil(t *testing.T) {
	c := NewCollector()
	defer c.Stop()
	got := c.Traffic(60)
	if got == nil {
		t.Fatal("Traffic() on an idle collector must be non-nil (marshals to [] not null)")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 buckets on an idle collector, got %d", len(got))
	}
}
