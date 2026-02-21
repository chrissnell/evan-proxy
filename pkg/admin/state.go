package admin

import "sync/atomic"

// ProxyState holds the atomic enabled/disabled flag for the proxy.
type ProxyState struct {
	enabled atomic.Bool
}

func NewProxyState() *ProxyState {
	s := &ProxyState{}
	s.enabled.Store(true) // starts enabled
	return s
}

func (s *ProxyState) IsEnabled() bool  { return s.enabled.Load() }
func (s *ProxyState) SetEnabled(v bool) { s.enabled.Store(v) }

// Toggle flips the state and returns the new value.
func (s *ProxyState) Toggle() bool {
	for {
		old := s.enabled.Load()
		if s.enabled.CompareAndSwap(old, !old) {
			return !old
		}
	}
}
