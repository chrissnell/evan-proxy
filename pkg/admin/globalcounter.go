package admin

import (
	"sync"
	"time"
)

// globalCounter is a sliding-window ceiling on total login failures across all
// client IPs. It backstops the per-IP limiter, which alone is weak against an
// attacker rotating source IPs at a single admin account. max <= 0 disables it.
type globalCounter struct {
	mu     sync.Mutex
	times  []time.Time
	max    int
	window time.Duration
}

func newGlobalCounter(max int, window time.Duration) *globalCounter {
	return &globalCounter{max: max, window: window}
}

// allow reports whether another failure is permitted within the window.
func (g *globalCounter) allow() bool {
	if g.max <= 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := time.Now().Add(-g.window)
	active := g.times[:0]
	for _, t := range g.times {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}
	g.times = active
	return len(active) < g.max
}

// record notes a failure at the current time.
func (g *globalCounter) record() {
	if g.max <= 0 {
		return
	}
	g.mu.Lock()
	g.times = append(g.times, time.Now())
	g.mu.Unlock()
}
