package logging

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestJSONHTTPBatchFlush(t *testing.T) {
	var mu sync.Mutex
	var batches [][]Message

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch []Message
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Errorf("invalid JSON: %v", err)
			w.WriteHeader(500)
			return
		}
		mu.Lock()
		batches = append(batches, batch)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Batch size of 3, long interval so we only trigger on size
	b := NewJSONHTTPBackend(srv.URL, 3, 10*time.Minute)

	b.Log(Message{Access: &Entry{Method: "GET", Host: "a.com", Status: 200}})
	b.Log(Message{Access: &Entry{Method: "GET", Host: "b.com", Status: 200}})
	b.Log(Message{Access: &Entry{Method: "GET", Host: "c.com", Status: 200}})

	// Wait for flush
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	n := len(batches)
	mu.Unlock()

	if n != 1 {
		t.Fatalf("expected 1 batch, got %d", n)
	}

	mu.Lock()
	batch := batches[0]
	mu.Unlock()

	if len(batch) != 3 {
		t.Errorf("expected 3 entries in batch, got %d", len(batch))
	}
}

func TestJSONHTTPIntervalFlush(t *testing.T) {
	var mu sync.Mutex
	var batches [][]Message

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch []Message
		json.Unmarshal(body, &batch)
		mu.Lock()
		batches = append(batches, batch)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Large batch size, short interval
	b := NewJSONHTTPBackend(srv.URL, 1000, 50*time.Millisecond)

	b.Log(Message{Server: &ServerMessage{Level: "info", Component: "test", Text: "hello"}})

	// Wait for interval flush
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	n := len(batches)
	mu.Unlock()

	if n < 1 {
		t.Fatal("expected at least 1 interval flush")
	}

	mu.Lock()
	if len(batches[0]) != 1 {
		t.Errorf("expected 1 entry, got %d", len(batches[0]))
	}
	mu.Unlock()
}

func TestJSONHTTPCloseFlushes(t *testing.T) {
	var mu sync.Mutex
	var batches [][]Message

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch []Message
		json.Unmarshal(body, &batch)
		mu.Lock()
		batches = append(batches, batch)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	b := NewJSONHTTPBackend(srv.URL, 1000, 10*time.Minute)
	b.Log(Message{Access: &Entry{Method: "GET", Host: "z.com", Status: 200}})

	b.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 1 {
		t.Fatalf("expected Close to flush 1 batch, got %d", len(batches))
	}
	if len(batches[0]) != 1 {
		t.Errorf("expected 1 entry, got %d", len(batches[0]))
	}
}
