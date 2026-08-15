package admin

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// demoEnrollCode is the fixed enrollment code minted in demo mode. It never
// expires and is reusable, so the pairing QR can be handed to App Store review
// and scanned repeatedly. Because it is a constant that newEnrollStore re-seeds
// on every start, the same code (and thus the same QR) survives pod restarts.
const demoEnrollCode = "demo-appstore-pair"

// enrollStore holds single-use, short-lived device enrollment codes in memory.
// An admin mints a code (rendered as a QR); the device redeems it once at
// /api/pair for a long-lived bearer token.
//
// In demo mode (persistent) the semantics change: codes never expire and a code
// may be redeemed any number of times, so App Store review can pair repeatedly
// from one persistent QR. create() always returns the fixed demoEnrollCode.
type enrollStore struct {
	ttl        time.Duration
	persistent bool // demo mode: codes never expire and are reusable
	stop       chan struct{}

	mu    sync.Mutex
	codes map[string]time.Time // code -> expiry (zero = never expires)
}

func newEnrollStore(ttl time.Duration, persistent bool) *enrollStore {
	es := &enrollStore{
		ttl:        ttl,
		persistent: persistent,
		stop:       make(chan struct{}),
		codes:      make(map[string]time.Time),
	}
	if persistent {
		es.codes[demoEnrollCode] = time.Time{} // seeded, never expires
	}
	go es.cleanup()
	return es
}

// live reports whether an expiry timestamp is still valid. A zero time means the
// code never expires (demo mode).
func live(exp time.Time) bool {
	return exp.IsZero() || time.Now().Before(exp)
}

// create mints an enrollment code. In demo mode it returns the fixed, persistent
// demoEnrollCode; otherwise a fresh random single-use code with the store's TTL.
func (es *enrollStore) create() string {
	if es.persistent {
		es.mu.Lock()
		es.codes[demoEnrollCode] = time.Time{}
		es.mu.Unlock()
		return demoEnrollCode
	}

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
	return ok && live(exp)
}

// consume redeems a live code. Normally a code redeems at most once; in demo
// mode (persistent) the code is left in place so it can be reused.
func (es *enrollStore) consume(code string) bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	exp, ok := es.codes[code]
	if !ok {
		return false
	}
	if !live(exp) {
		delete(es.codes, code)
		return false
	}
	if !es.persistent {
		delete(es.codes, code)
	}
	return true
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
				if !exp.IsZero() && now.After(exp) {
					delete(es.codes, code)
				}
			}
			es.mu.Unlock()
		case <-es.stop:
			return
		}
	}
}
