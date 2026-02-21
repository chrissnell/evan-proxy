package admin

import (
	"testing"
	"time"
)

func TestCreateAndValidate(t *testing.T) {
	ss := NewSessionStore(time.Hour)
	defer ss.Stop()

	token := ss.Create()
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if !ss.Validate(token) {
		t.Error("expected new session to validate")
	}
}

func TestInvalidToken(t *testing.T) {
	ss := NewSessionStore(time.Hour)
	defer ss.Stop()

	if ss.Validate("nonexistent") {
		t.Error("expected unknown token to fail validation")
	}
}

func TestDelete(t *testing.T) {
	ss := NewSessionStore(time.Hour)
	defer ss.Stop()

	token := ss.Create()
	ss.Delete(token)
	if ss.Validate(token) {
		t.Error("expected deleted session to fail validation")
	}
}

func TestExpiredSession(t *testing.T) {
	ss := NewSessionStore(10 * time.Millisecond)
	defer ss.Stop()

	token := ss.Create()
	time.Sleep(20 * time.Millisecond)
	if ss.Validate(token) {
		t.Error("expected expired session to fail validation")
	}
}

func TestMultipleSessions(t *testing.T) {
	ss := NewSessionStore(time.Hour)
	defer ss.Stop()

	t1 := ss.Create()
	t2 := ss.Create()
	if t1 == t2 {
		t.Error("expected unique tokens")
	}
	if !ss.Validate(t1) || !ss.Validate(t2) {
		t.Error("expected both sessions to validate")
	}
}
