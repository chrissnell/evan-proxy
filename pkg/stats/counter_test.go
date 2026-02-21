package stats

import (
	"bytes"
	"testing"
	"time"
)

func TestCountingWriterTotal(t *testing.T) {
	c := NewCollector()
	defer c.Stop()
	tc := NewTrafficCounter(c)
	defer tc.Stop()

	var buf bytes.Buffer
	cw := tc.NewWriter(&buf, false)

	data := []byte("hello world")
	n, err := cw.Write(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Fatalf("expected %d bytes written, got %d", len(data), n)
	}

	cw.Close()

	if cw.Total() != int64(len(data)) {
		t.Errorf("expected total %d, got %d", len(data), cw.Total())
	}
	if buf.String() != "hello world" {
		t.Errorf("expected %q in buffer, got %q", "hello world", buf.String())
	}
}

func TestCountingWriterMultipleWrites(t *testing.T) {
	c := NewCollector()
	defer c.Stop()
	tc := NewTrafficCounter(c)
	defer tc.Stop()

	var buf bytes.Buffer
	cw := tc.NewWriter(&buf, false)

	cw.Write([]byte("aaa"))
	cw.Write([]byte("bbb"))
	cw.Write([]byte("ccc"))
	cw.Close()

	if cw.Total() != 9 {
		t.Errorf("expected total 9, got %d", cw.Total())
	}
}

func TestCountingWriterFlushesToCollector(t *testing.T) {
	c := NewCollector()
	defer c.Stop()
	tc := NewTrafficCounter(c)
	defer tc.Stop()

	var buf bytes.Buffer
	cw := tc.NewWriter(&buf, false)

	// Write enough to be interesting
	cw.Write(make([]byte, 1024))
	cw.Close()

	// Give drain goroutine time to process
	time.Sleep(50 * time.Millisecond)

	traffic := c.Traffic(60)
	if len(traffic) == 0 {
		t.Fatal("expected at least 1 traffic bucket")
	}

	var totalWritten int64
	for _, b := range traffic {
		totalWritten += b.BytesWritten
	}
	if totalWritten != 1024 {
		t.Errorf("expected 1024 bytes in traffic buckets, got %d", totalWritten)
	}
}

func TestCountingWriterReadDirection(t *testing.T) {
	c := NewCollector()
	defer c.Stop()
	tc := NewTrafficCounter(c)
	defer tc.Stop()

	var buf bytes.Buffer
	cw := tc.NewWriter(&buf, true) // isRead=true

	cw.Write(make([]byte, 512))
	cw.Close()

	time.Sleep(50 * time.Millisecond)

	traffic := c.Traffic(60)
	if len(traffic) == 0 {
		t.Fatal("expected at least 1 traffic bucket")
	}

	var totalRead int64
	for _, b := range traffic {
		totalRead += b.BytesRead
	}
	if totalRead != 512 {
		t.Errorf("expected 512 bytes read in traffic buckets, got %d", totalRead)
	}
}

func TestAddLiveBytesNewBucket(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	c.AddLiveBytes(100, 200)

	traffic := c.Traffic(60)
	if len(traffic) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(traffic))
	}
	if traffic[0].BytesRead != 100 {
		t.Errorf("expected 100 bytes read, got %d", traffic[0].BytesRead)
	}
	if traffic[0].BytesWritten != 200 {
		t.Errorf("expected 200 bytes written, got %d", traffic[0].BytesWritten)
	}
}

func TestAddLiveBytesExistingBucket(t *testing.T) {
	c := NewCollector()
	defer c.Stop()

	c.AddLiveBytes(100, 200)
	c.AddLiveBytes(50, 75)

	traffic := c.Traffic(60)
	if len(traffic) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(traffic))
	}
	if traffic[0].BytesRead != 150 {
		t.Errorf("expected 150 bytes read, got %d", traffic[0].BytesRead)
	}
	if traffic[0].BytesWritten != 275 {
		t.Errorf("expected 275 bytes written, got %d", traffic[0].BytesWritten)
	}
}

func TestLiveFlushInterval(t *testing.T) {
	c := NewCollector()
	defer c.Stop()
	tc := NewTrafficCounter(c)
	defer tc.Stop()

	var buf bytes.Buffer
	cw := tc.NewWriter(&buf, false)

	// Write data and wait for a flush cycle
	cw.Write(make([]byte, 2048))
	time.Sleep(1200 * time.Millisecond)

	// Check that bytes appeared in collector before Close
	traffic := c.Traffic(60)
	var totalWritten int64
	for _, b := range traffic {
		totalWritten += b.BytesWritten
	}
	if totalWritten != 2048 {
		t.Errorf("expected 2048 bytes after flush interval, got %d", totalWritten)
	}

	cw.Close()
}
