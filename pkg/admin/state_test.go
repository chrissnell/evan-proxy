package admin

import "testing"

func TestDefaultEnabled(t *testing.T) {
	s := NewProxyState()
	if !s.IsEnabled() {
		t.Error("expected default state to be enabled")
	}
}

func TestToggle(t *testing.T) {
	s := NewProxyState()

	got := s.Toggle()
	if got != false {
		t.Errorf("first toggle: got %v, want false", got)
	}
	if s.IsEnabled() {
		t.Error("expected disabled after first toggle")
	}

	got = s.Toggle()
	if got != true {
		t.Errorf("second toggle: got %v, want true", got)
	}
	if !s.IsEnabled() {
		t.Error("expected enabled after second toggle")
	}
}

func TestSetEnabled(t *testing.T) {
	s := NewProxyState()
	s.SetEnabled(false)
	if s.IsEnabled() {
		t.Error("expected disabled after SetEnabled(false)")
	}
	s.SetEnabled(true)
	if !s.IsEnabled() {
		t.Error("expected enabled after SetEnabled(true)")
	}
}
