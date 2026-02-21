package stats

import (
	"io"
	"sync/atomic"
	"time"
)

const (
	flushInterval = 1 * time.Second
	liveChanSize  = 256
)

// TrafficDelta represents a chunk of bytes flowing through the proxy.
type TrafficDelta struct {
	Read    int64
	Written int64
}

// TrafficCounter collects live byte counts from counting writers
// and drains them into a collector via a buffered channel.
type TrafficCounter struct {
	ch     chan TrafficDelta
	stopCh chan struct{}
}

func NewTrafficCounter(c *Collector) *TrafficCounter {
	tc := &TrafficCounter{
		ch:     make(chan TrafficDelta, liveChanSize),
		stopCh: make(chan struct{}),
	}
	go tc.drain(c)
	return tc
}

func (tc *TrafficCounter) Stop() {
	close(tc.stopCh)
}

// NewWriter wraps w in a CountingWriter that flushes byte counts
// to the traffic channel every flushInterval.
func (tc *TrafficCounter) NewWriter(w io.Writer, isRead bool) *CountingWriter {
	cw := &CountingWriter{
		w:      w,
		isRead: isRead,
		ch:     tc.ch,
	}
	cw.startFlusher()
	return cw
}

func (tc *TrafficCounter) drain(c *Collector) {
	for {
		select {
		case d := <-tc.ch:
			c.AddLiveBytes(d.Read, d.Written)
		case <-tc.stopCh:
			for {
				select {
				case d := <-tc.ch:
					c.AddLiveBytes(d.Read, d.Written)
				default:
					return
				}
			}
		}
	}
}

// CountingWriter wraps an io.Writer and periodically flushes
// accumulated byte counts to a channel.
type CountingWriter struct {
	w       io.Writer
	isRead  bool
	ch      chan TrafficDelta
	pending atomic.Int64 // bytes since last flush
	total   atomic.Int64 // monotonically increasing total
	stopCh  chan struct{}
}

func (cw *CountingWriter) startFlusher() {
	cw.stopCh = make(chan struct{})
	go func() {
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cw.flush()
			case <-cw.stopCh:
				cw.flush()
				return
			}
		}
	}()
}

func (cw *CountingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.pending.Add(int64(n))
		cw.total.Add(int64(n))
	}
	return n, err
}

// Close stops the flusher and sends any remaining bytes.
func (cw *CountingWriter) Close() {
	close(cw.stopCh)
}

// Total returns the cumulative bytes passed through this writer.
func (cw *CountingWriter) Total() int64 {
	return cw.total.Load()
}

func (cw *CountingWriter) flush() {
	n := cw.pending.Swap(0)
	if n == 0 {
		return
	}
	d := TrafficDelta{}
	if cw.isRead {
		d.Read = n
	} else {
		d.Written = n
	}
	select {
	case cw.ch <- d:
	default:
	}
}
