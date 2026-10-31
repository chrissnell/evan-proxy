package mitm

import (
	"container/list"
	"crypto/tls"
	"sync"
)

// certCache is a count-bounded LRU of minted leaf certificates keyed by the
// handshake identity (SNI, or the CONNECT target when the client sent no SNI).
// In-memory only: certificates are cheap to re-mint and a pod restart should
// not inherit certs signed by a CA that may since have rotated.
type certCache struct {
	mu     sync.Mutex
	max    int
	order  *list.List // front = most recently used; values are *cacheEntry
	index  map[string]*list.Element
	hits   uint64
	misses uint64
}

type cacheEntry struct {
	key  string
	cert *tls.Certificate
}

func newCertCache(max int) *certCache {
	if max < 1 {
		max = 1
	}
	return &certCache{
		max:   max,
		order: list.New(),
		index: make(map[string]*list.Element, max),
	}
}

// get returns the cached certificate for key, promoting it to most-recently-used.
func (c *certCache) get(key string) (*tls.Certificate, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.index[key]
	if !ok {
		c.misses++
		return nil, false
	}
	c.order.MoveToFront(el)
	c.hits++
	return el.Value.(*cacheEntry).cert, true
}

// put stores cert under key, evicting the least recently used entry if full.
func (c *certCache) put(key string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.index[key]; ok {
		el.Value.(*cacheEntry).cert = cert
		c.order.MoveToFront(el)
		return
	}

	c.index[key] = c.order.PushFront(&cacheEntry{key: key, cert: cert})
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.index, oldest.Value.(*cacheEntry).key)
	}
}

// purge drops every cached certificate. Called on CA rotation: leaves signed by
// the retired CA are no longer validatable by the device.
func (c *certCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	c.index = make(map[string]*list.Element, c.max)
}

func (c *certCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// stats returns cumulative hit and miss counts. Counters survive purge so the
// numbers read as lifetime process totals, which is what Prometheus wants.
func (c *certCache) stats() (hits, misses uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}
