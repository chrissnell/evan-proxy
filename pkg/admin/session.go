package admin

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"evan-proxy/pkg/logging"
)

const sessionCookie = "evan-proxy-session"

type session struct {
	expiresAt time.Time
}

// SessionStore manages admin sessions in memory.
type SessionStore struct {
	ttl    time.Duration
	stop   chan struct{}
	logger *logging.Logger

	mu       sync.RWMutex
	sessions map[string]session
}

func NewSessionStore(ttl time.Duration, lg *logging.Logger) *SessionStore {
	ss := &SessionStore{
		ttl:      ttl,
		stop:     make(chan struct{}),
		logger:   lg,
		sessions: make(map[string]session),
	}
	go ss.cleanup()
	return ss
}

// Create generates a new session token.
func (ss *SessionStore) Create() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	ss.mu.Lock()
	ss.sessions[token] = session{expiresAt: time.Now().Add(ss.ttl)}
	ss.mu.Unlock()

	return token
}

// Validate checks if a session token is valid and renews its expiration.
func (ss *SessionStore) Validate(token string) bool {
	now := time.Now()

	ss.mu.RLock()
	s, found := ss.sessions[token]
	ss.mu.RUnlock()

	if !found {
		return false
	}
	if now.After(s.expiresAt) {
		ss.mu.Lock()
		delete(ss.sessions, token)
		ss.mu.Unlock()
		return false
	}

	// Sliding expiration
	ss.mu.Lock()
	ss.sessions[token] = session{expiresAt: now.Add(ss.ttl)}
	ss.mu.Unlock()
	return true
}

// Delete removes a session.
func (ss *SessionStore) Delete(token string) {
	ss.mu.Lock()
	delete(ss.sessions, token)
	ss.mu.Unlock()
}

// Stop terminates the background cleanup goroutine.
func (ss *SessionStore) Stop() {
	close(ss.stop)
}

func (ss *SessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			ss.mu.Lock()
			for token, s := range ss.sessions {
				if now.After(s.expiresAt) {
					delete(ss.sessions, token)
				}
			}
			ss.mu.Unlock()
		case <-ss.stop:
			return
		}
	}
}
