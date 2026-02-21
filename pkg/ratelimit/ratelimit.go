package ratelimit

import (
	"sync"
	"time"
)

// Limiter tracks auth failures per client IP using a sliding window.
type Limiter struct {
	mu     sync.Mutex
	counts map[string][]time.Time
	limit  int
	window time.Duration
	stop   chan struct{}
}

func New(limit int, window time.Duration) *Limiter {
	l := &Limiter{
		counts: make(map[string][]time.Time),
		limit:  limit,
		window: window,
		stop:   make(chan struct{}),
	}
	go l.cleanup()
	return l
}

// RecordFailure records an auth failure for the given IP.
func (l *Limiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[ip] = append(l.counts[ip], time.Now())
}

// Allow returns true if the IP has not exceeded the failure limit.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	times, ok := l.counts[ip]
	if !ok {
		return true
	}

	cutoff := time.Now().Add(-l.window)
	active := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}
	l.counts[ip] = active

	return len(active) < l.limit
}

// Stop terminates the background cleanup goroutine.
func (l *Limiter) Stop() {
	close(l.stop)
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-l.window)
			for ip, times := range l.counts {
				active := times[:0]
				for _, t := range times {
					if t.After(cutoff) {
						active = append(active, t)
					}
				}
				if len(active) == 0 {
					delete(l.counts, ip)
				} else {
					l.counts[ip] = active
				}
			}
			l.mu.Unlock()
		case <-l.stop:
			return
		}
	}
}
