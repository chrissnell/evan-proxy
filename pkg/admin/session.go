package admin

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const sessionCookie = "evan-proxy-session"

type session struct {
	token     string
	expiresAt time.Time
}

// SessionStore manages admin sessions in memory.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
	ttl      time.Duration
	stop     chan struct{}
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	ss := &SessionStore{
		sessions: make(map[string]*session),
		ttl:      ttl,
		stop:     make(chan struct{}),
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
	ss.sessions[token] = &session{
		token:     token,
		expiresAt: time.Now().Add(ss.ttl),
	}
	ss.mu.Unlock()
	return token
}

// Validate checks if a session token is valid and not expired.
func (ss *SessionStore) Validate(token string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	s, ok := ss.sessions[token]
	if !ok {
		return false
	}
	now := time.Now()
	if now.After(s.expiresAt) {
		delete(ss.sessions, token)
		return false
	}
	// Sliding expiration: renew on each valid access
	s.expiresAt = now.Add(ss.ttl)
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
			ss.mu.Lock()
			now := time.Now()
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
