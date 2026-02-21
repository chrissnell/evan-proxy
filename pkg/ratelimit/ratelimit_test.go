package ratelimit

import (
	"testing"
	"time"
)

func TestAllowUnderLimit(t *testing.T) {
	l := New(3, time.Minute)
	defer l.Stop()

	l.RecordFailure("1.2.3.4")
	l.RecordFailure("1.2.3.4")
	if !l.Allow("1.2.3.4") {
		t.Error("expected Allow with 2 failures under limit of 3")
	}
}

func TestBlockOverLimit(t *testing.T) {
	l := New(3, time.Minute)
	defer l.Stop()

	for i := 0; i < 3; i++ {
		l.RecordFailure("1.2.3.4")
	}
	if l.Allow("1.2.3.4") {
		t.Error("expected block at limit of 3")
	}
}

func TestDifferentIPs(t *testing.T) {
	l := New(2, time.Minute)
	defer l.Stop()

	l.RecordFailure("1.1.1.1")
	l.RecordFailure("1.1.1.1")
	l.RecordFailure("2.2.2.2")

	if l.Allow("1.1.1.1") {
		t.Error("expected 1.1.1.1 to be blocked")
	}
	if !l.Allow("2.2.2.2") {
		t.Error("expected 2.2.2.2 to be allowed")
	}
}

func TestWindowExpiry(t *testing.T) {
	l := New(2, 50*time.Millisecond)
	defer l.Stop()

	l.RecordFailure("1.2.3.4")
	l.RecordFailure("1.2.3.4")
	if l.Allow("1.2.3.4") {
		t.Error("expected block immediately")
	}

	time.Sleep(60 * time.Millisecond)
	if !l.Allow("1.2.3.4") {
		t.Error("expected Allow after window expiry")
	}
}

func TestUnknownIPAllowed(t *testing.T) {
	l := New(3, time.Minute)
	defer l.Stop()

	if !l.Allow("5.5.5.5") {
		t.Error("expected unknown IP to be allowed")
	}
}
