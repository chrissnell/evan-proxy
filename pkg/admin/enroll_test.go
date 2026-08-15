package admin

import (
	"testing"
	"time"
)

func TestEnrollStore_SingleUseAndExpiry(t *testing.T) {
	es := newEnrollStore(50*time.Millisecond, false)
	defer es.Stop()

	code := es.create()
	if code == "" {
		t.Fatal("empty code")
	}
	if !es.peek(code) {
		t.Fatal("peek should see a live code")
	}
	if !es.consume(code) {
		t.Fatal("first consume should succeed")
	}
	if es.peek(code) {
		t.Fatal("consumed code should not peek")
	}
	if es.consume(code) {
		t.Fatal("code must be single-use")
	}

	code2 := es.create()
	time.Sleep(60 * time.Millisecond)
	if es.peek(code2) {
		t.Fatal("expired code must not peek")
	}
	if es.consume(code2) {
		t.Fatal("expired code must not consume")
	}
}

func TestEnrollStore_DemoPersistent(t *testing.T) {
	// Short TTL proves the demo code ignores expiry.
	es := newEnrollStore(10*time.Millisecond, true)
	defer es.Stop()

	code := es.create()
	if code != demoEnrollCode {
		t.Fatalf("demo mode should mint the fixed code %q, got %q", demoEnrollCode, code)
	}

	// The fixed code exists before any create() call (seeded at construction).
	es2 := newEnrollStore(10*time.Millisecond, true)
	defer es2.Stop()
	if !es2.peek(demoEnrollCode) {
		t.Fatal("demo code should be live immediately after construction")
	}

	// Reusable: consuming does not invalidate it.
	if !es.consume(code) {
		t.Fatal("first consume should succeed")
	}
	if !es.consume(code) {
		t.Fatal("demo code must be reusable (second consume should succeed)")
	}

	// Non-expiring: still live well past the TTL.
	time.Sleep(20 * time.Millisecond)
	if !es.peek(code) {
		t.Fatal("demo code must not expire")
	}
	if !es.consume(code) {
		t.Fatal("demo code must still consume after the TTL window")
	}
}
