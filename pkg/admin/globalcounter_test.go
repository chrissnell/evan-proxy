package admin

import (
	"testing"
	"time"
)

func TestGlobalCounter_CeilingAndWindow(t *testing.T) {
	g := newGlobalCounter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !g.allow() {
			t.Fatalf("allow %d: want true (under ceiling)", i)
		}
		g.record()
	}
	if g.allow() {
		t.Fatal("want false once ceiling reached")
	}
}

func TestGlobalCounter_PrunesExpired(t *testing.T) {
	g := newGlobalCounter(2, 20*time.Millisecond)
	g.record()
	g.record()
	if g.allow() {
		t.Fatal("want false at ceiling")
	}
	time.Sleep(30 * time.Millisecond)
	if !g.allow() {
		t.Fatal("want true after window elapsed (old failures pruned)")
	}
}

func TestGlobalCounter_DisabledWhenMaxZero(t *testing.T) {
	g := newGlobalCounter(0, time.Minute)
	for i := 0; i < 1000; i++ {
		g.record()
		if !g.allow() {
			t.Fatal("max<=0 must never block")
		}
	}
}
