package admin

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// enrollStore holds single-use, short-lived device enrollment codes in memory.
// An admin mints a code (rendered as a QR); the device redeems it once at
// /api/pair for a long-lived bearer token.
type enrollStore struct {
	ttl  time.Duration
	stop chan struct{}

	mu    sync.Mutex
	codes map[string]time.Time // code -> expiry
}

func newEnrollStore(ttl time.Duration) *enrollStore {
	es := &enrollStore{
		ttl:   ttl,
		stop:  make(chan struct{}),
		codes: make(map[string]time.Time),
	}
	go es.cleanup()
	return es
}

// create mints a random URL-safe enrollment code.
func (es *enrollStore) create() string {
	b := make([]byte, 16)
	rand.Read(b)
	code := base64.RawURLEncoding.EncodeToString(b)

	es.mu.Lock()
	es.codes[code] = time.Now().Add(es.ttl)
	es.mu.Unlock()

	return code
}

// peek reports whether code is live without consuming it (used to render the QR).
func (es *enrollStore) peek(code string) bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	exp, ok := es.codes[code]
	return ok && time.Now().Before(exp)
}

// consume atomically redeems a live code; a code redeems at most once.
func (es *enrollStore) consume(code string) bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	exp, ok := es.codes[code]
	if !ok {
		return false
	}
	delete(es.codes, code)
	return time.Now().Before(exp)
}

// Stop terminates the background cleanup goroutine.
func (es *enrollStore) Stop() {
	close(es.stop)
}

func (es *enrollStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			es.mu.Lock()
			for code, exp := range es.codes {
				if now.After(exp) {
					delete(es.codes, code)
				}
			}
			es.mu.Unlock()
		case <-es.stop:
			return
		}
	}
}
