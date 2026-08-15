package stats

import (
	"net"
	"sort"
	"sync"
	"time"

	"evan-proxy/pkg/logging"
)

const (
	window        = 1 * time.Hour
	bucketWidth   = 10 * time.Second
	maxBuckets    = 360 // 1 hour of 10s buckets
	cleanupPeriod = 30 * time.Second
	subBufSize    = 64
)

type hostHit struct {
	host string
	ts   time.Time
}

type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

type TrafficBucket struct {
	Time         int64 `json:"t"`
	Requests     int   `json:"reqs"`
	BytesRead    int64 `json:"br"`
	BytesWritten int64 `json:"bw"`
}

type Collector struct {
	mu        sync.RWMutex
	hostHits  []hostHit
	dnsBlocks []hostHit
	buckets   [maxBuckets]TrafficBucket
	bucketIdx int
	logSubs   map[chan logging.Entry]struct{}
	stopCh    chan struct{}
}

func NewCollector() *Collector {
	c := &Collector{
		logSubs: make(map[chan logging.Entry]struct{}),
		stopCh:  make(chan struct{}),
	}
	go c.cleanup()
	return c
}

// Observe is registered as a logger observer. Must not block.
func (c *Collector) Observe(e logging.Entry) {
	c.mu.Lock()

	// Track successful host visits (skip auth failures, rate limits)
	if e.Status < 400 && e.Host != "" {
		c.hostHits = append(c.hostHits, hostHit{host: hostOnly(e.Host), ts: e.Timestamp})
	}

	// Track DNS blocks
	if e.Event == "dns-block" {
		c.dnsBlocks = append(c.dnsBlocks, hostHit{host: hostOnly(e.Host), ts: e.Timestamp})
	}

	c.recordTraffic(e)

	// Fan out to SSE subscribers
	for ch := range c.logSubs {
		select {
		case ch <- e:
		default:
		}
	}

	c.mu.Unlock()
}

func (c *Collector) recordTraffic(e logging.Entry) {
	bucketTime := e.Timestamp.Truncate(bucketWidth)
	bt := bucketTime.Unix()

	cur := &c.buckets[c.bucketIdx]
	if cur.Time == bt {
		cur.Requests++
		cur.BytesRead += e.BytesRead
		cur.BytesWritten += e.BytesWritten
		return
	}

	if cur.Time == 0 || bt > cur.Time {
		// Advance to next bucket
		c.bucketIdx = (c.bucketIdx + 1) % maxBuckets
		c.buckets[c.bucketIdx] = TrafficBucket{
			Time:         bt,
			Requests:     1,
			BytesRead:    e.BytesRead,
			BytesWritten: e.BytesWritten,
		}
	}
}

// AddLiveBytes adds in-flight byte counts to the current traffic bucket.
// Called from the TrafficCounter drain goroutine.
func (c *Collector) AddLiveBytes(read, written int64) {
	c.mu.Lock()
	now := time.Now().Truncate(bucketWidth).Unix()
	cur := &c.buckets[c.bucketIdx]
	if cur.Time == now {
		cur.BytesRead += read
		cur.BytesWritten += written
	} else if cur.Time == 0 || now > cur.Time {
		c.bucketIdx = (c.bucketIdx + 1) % maxBuckets
		c.buckets[c.bucketIdx] = TrafficBucket{
			Time:         now,
			BytesRead:    read,
			BytesWritten: written,
		}
	}
	c.mu.Unlock()
}

func (c *Collector) TopHosts(n int) []HostCount {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	counts := make(map[string]int)
	for _, h := range c.hostHits {
		if h.ts.After(cutoff) {
			counts[h.host]++
		}
	}
	return topN(counts, n)
}

func (c *Collector) TopBlocked(n int) []HostCount {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	counts := make(map[string]int)
	for _, h := range c.dnsBlocks {
		if h.ts.After(cutoff) {
			counts[h.host]++
		}
	}
	return topN(counts, n)
}

func (c *Collector) Traffic(count int) []TrafficBucket {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if count > maxBuckets {
		count = maxBuckets
	}

	// Collect non-zero buckets in chronological order. Non-nil so an idle
	// server marshals to a JSON [] rather than null — strict clients (the iOS
	// app's generated OpenAPI decoder) reject null for a non-nullable array.
	result := make([]TrafficBucket, 0, maxBuckets)
	for i := 0; i < maxBuckets; i++ {
		idx := (c.bucketIdx + 1 + i) % maxBuckets
		b := c.buckets[idx]
		if b.Time > 0 {
			result = append(result, b)
		}
	}

	if len(result) > count {
		result = result[len(result)-count:]
	}
	return result
}

func (c *Collector) Subscribe() chan logging.Entry {
	ch := make(chan logging.Entry, subBufSize)
	c.mu.Lock()
	c.logSubs[ch] = struct{}{}
	c.mu.Unlock()
	return ch
}

func (c *Collector) Unsubscribe(ch chan logging.Entry) {
	c.mu.Lock()
	delete(c.logSubs, ch)
	c.mu.Unlock()
	close(ch)
}

func (c *Collector) Stop() {
	close(c.stopCh)
}

func (c *Collector) cleanup() {
	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.compact()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Collector) compact() {
	cutoff := time.Now().Add(-window)
	c.mu.Lock()
	defer c.mu.Unlock()

	c.hostHits = compactHits(c.hostHits, cutoff)
	c.dnsBlocks = compactHits(c.dnsBlocks, cutoff)
}

func compactHits(hits []hostHit, cutoff time.Time) []hostHit {
	n := 0
	for _, h := range hits {
		if h.ts.After(cutoff) {
			hits[n] = h
			n++
		}
	}
	return hits[:n]
}

func topN(counts map[string]int, n int) []HostCount {
	result := make([]HostCount, 0, len(counts))
	for host, count := range counts {
		result = append(result, HostCount{Host: host, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
