package mitm

import (
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
)

func TestCertCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := newCertCache(2)
	a, b, d := &tls.Certificate{}, &tls.Certificate{}, &tls.Certificate{}

	c.put("a", a)
	c.put("b", b)

	// Touch "a" so "b" becomes the eviction candidate.
	if got, ok := c.get("a"); !ok || got != a {
		t.Fatal("a missing after put")
	}
	c.put("d", d)

	if _, ok := c.get("b"); ok {
		t.Error("b survived eviction despite being least recently used")
	}
	if _, ok := c.get("a"); !ok {
		t.Error("a was evicted even though it was used most recently")
	}
	if n := c.len(); n != 2 {
		t.Errorf("len = %d, want 2", n)
	}
}

func TestCertCacheOverwriteDoesNotGrow(t *testing.T) {
	c := newCertCache(4)
	first, second := &tls.Certificate{}, &tls.Certificate{}

	c.put("a", first)
	c.put("a", second)

	if n := c.len(); n != 1 {
		t.Errorf("len = %d, want 1 after overwriting the same key", n)
	}
	if got, _ := c.get("a"); got != second {
		t.Error("overwrite did not replace the cached certificate")
	}
}

func TestCertCachePurge(t *testing.T) {
	c := newCertCache(4)
	c.put("a", &tls.Certificate{})
	c.put("b", &tls.Certificate{})

	c.purge()

	if n := c.len(); n != 0 {
		t.Errorf("len = %d after purge, want 0", n)
	}
	if _, ok := c.get("a"); ok {
		t.Error("purge left an entry behind")
	}
	// Counters are lifetime process totals, so purge must not reset them.
	if hits, misses := c.stats(); hits != 0 || misses != 1 {
		t.Errorf("stats = (%d, %d), want (0, 1)", hits, misses)
	}
}

func TestCertCacheMinimumSize(t *testing.T) {
	for _, max := range []int{0, -1} {
		c := newCertCache(max)
		c.put("a", &tls.Certificate{})
		if n := c.len(); n != 1 {
			t.Errorf("newCertCache(%d): len = %d, want a floor of 1 entry", max, n)
		}
	}
}

func TestCertCacheConcurrentAccess(t *testing.T) {
	c := newCertCache(16)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				key := fmt.Sprintf("host-%d", j%32)
				if _, ok := c.get(key); !ok {
					c.put(key, &tls.Certificate{})
				}
			}
		}(i)
	}
	wg.Wait()

	if n := c.len(); n > 16 {
		t.Errorf("len = %d, exceeds the bound of 16", n)
	}
}
