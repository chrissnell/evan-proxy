package admin

import (
	"testing"
	"time"
)

func TestEnrollStore_SingleUseAndExpiry(t *testing.T) {
	es := newEnrollStore(50 * time.Millisecond)
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
