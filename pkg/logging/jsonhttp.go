package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// JSONHTTPBackend buffers log messages and periodically flushes them
// as a JSON array via HTTP POST.
type JSONHTTPBackend struct {
	url       string
	client    *http.Client
	batchSize int

	mu     sync.Mutex
	buf    []Message
	flush  chan struct{} // signal immediate flush
	done   chan struct{} // closed when background goroutine exits
	stopCh chan struct{} // signal shutdown
}

func NewJSONHTTPBackend(url string, batchSize int, flushInterval time.Duration) *JSONHTTPBackend {
	b := &JSONHTTPBackend{
		url:       url,
		client:    &http.Client{Timeout: 10 * time.Second},
		batchSize: batchSize,
		flush:     make(chan struct{}, 1),
		done:      make(chan struct{}),
		stopCh:    make(chan struct{}),
	}
	go b.run(flushInterval)
	return b
}

func (b *JSONHTTPBackend) Log(msg Message) {
	b.mu.Lock()
	b.buf = append(b.buf, msg)
	shouldFlush := len(b.buf) >= b.batchSize
	b.mu.Unlock()

	if shouldFlush {
		select {
		case b.flush <- struct{}{}:
		default:
		}
	}
}

func (b *JSONHTTPBackend) run(interval time.Duration) {
	defer close(b.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.doFlush()
		case <-b.flush:
			b.doFlush()
		case <-b.stopCh:
			b.doFlush()
			return
		}
	}
}

func (b *JSONHTTPBackend) doFlush() {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.buf
	b.buf = nil
	b.mu.Unlock()

	data, err := json.Marshal(batch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "jsonhttp: marshal error: %v\n", err)
		return
	}

	resp, err := b.client.Post(b.url, "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "jsonhttp: post error: %v\n", err)
		return
	}
	resp.Body.Close()
}

func (b *JSONHTTPBackend) Close() error {
	close(b.stopCh)
	<-b.done
	return nil
}
