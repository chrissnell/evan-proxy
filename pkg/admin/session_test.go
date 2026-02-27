package admin

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"evan-proxy/pkg/logging"
)

func newTestSessionStore(t *testing.T, ttl time.Duration) *SessionStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	lg := logging.New(logging.NewConsoleBackend(io.Discard, "human"))
	ss, err := NewSessionStore(dbPath, ttl, lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Stop() })
	return ss
}

func TestCreateAndValidate(t *testing.T) {
	ss := newTestSessionStore(t, time.Hour)

	token := ss.Create()
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if !ss.Validate(token) {
		t.Error("expected new session to validate")
	}
}

func TestInvalidToken(t *testing.T) {
	ss := newTestSessionStore(t, time.Hour)

	if ss.Validate("nonexistent") {
		t.Error("expected unknown token to fail validation")
	}
}

func TestDelete(t *testing.T) {
	ss := newTestSessionStore(t, time.Hour)

	token := ss.Create()
	ss.Delete(token)
	if ss.Validate(token) {
		t.Error("expected deleted session to fail validation")
	}
}

func TestExpiredSession(t *testing.T) {
	ss := newTestSessionStore(t, 10*time.Millisecond)

	token := ss.Create()
	time.Sleep(20 * time.Millisecond)
	if ss.Validate(token) {
		t.Error("expected expired session to fail validation")
	}
}

func TestMultipleSessions(t *testing.T) {
	ss := newTestSessionStore(t, time.Hour)

	t1 := ss.Create()
	t2 := ss.Create()
	if t1 == t2 {
		t.Error("expected unique tokens")
	}
	if !ss.Validate(t1) || !ss.Validate(t2) {
		t.Error("expected both sessions to validate")
	}
}
