package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsoleBackend(&buf, "json")
	l := New(c)

	ts := time.Date(2026, 2, 20, 14, 30, 0, 123000000, time.UTC)
	l.Log(Entry{
		Timestamp: ts, ClientIP: "10.0.0.1", Method: "CONNECT",
		Host: "example.com:443", User: "alice", Status: 200,
		DurationMS: 1234, BytesRead: 100, BytesWritten: 200,
	})

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, buf.String())
	}

	if parsed["client_ip"] != "10.0.0.1" {
		t.Errorf("client_ip = %v", parsed["client_ip"])
	}
	if parsed["method"] != "CONNECT" {
		t.Errorf("method = %v", parsed["method"])
	}
	if parsed["user"] != "alice" {
		t.Errorf("user = %v", parsed["user"])
	}
}

func TestHumanFormat(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsoleBackend(&buf, "human")
	l := New(c)

	ts := time.Date(2026, 2, 20, 14, 30, 0, 123000000, time.UTC)
	l.Log(Entry{
		Timestamp: ts, ClientIP: "10.0.0.1", Method: "GET",
		Host: "example.com", URI: "http://example.com/path",
		User: "bob", Status: 200, DurationMS: 42,
		BytesWritten: 512,
	})

	line := buf.String()
	if !strings.Contains(line, "2026-02-20T14:30:00.123Z") {
		t.Errorf("missing timestamp in: %s", line)
	}
	if !strings.Contains(line, "GET") {
		t.Errorf("missing method in: %s", line)
	}
	if !strings.Contains(line, "bob") {
		t.Errorf("missing user in: %s", line)
	}
}

func TestHumanFormatNoUser(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsoleBackend(&buf, "human")
	l := New(c)

	l.Log(Entry{
		Timestamp: time.Now(), ClientIP: "10.0.0.1", Method: "CONNECT",
		Host: "example.com:443", Status: 407,
	})

	if !strings.Contains(buf.String(), "-") {
		t.Errorf("expected '-' for empty user in: %s", buf.String())
	}
}

func TestFanOut(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	c1 := NewConsoleBackend(&buf1, "json")
	c2 := NewConsoleBackend(&buf2, "json")
	l := New(c1, c2)

	l.Log(Entry{
		Timestamp: time.Now(), ClientIP: "10.0.0.1", Method: "GET",
		Host: "example.com", Status: 200,
	})

	if buf1.Len() == 0 {
		t.Error("backend 1 received nothing")
	}
	if buf2.Len() == 0 {
		t.Error("backend 2 received nothing")
	}
}

func TestObserversOnlyAccessLogs(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsoleBackend(&buf, "json")
	l := New(c)

	var observed []Entry
	l.AddObserver(func(e Entry) {
		observed = append(observed, e)
	})

	l.Log(Entry{Timestamp: time.Now(), Method: "GET", Host: "example.com", Status: 200})
	l.Infof("test", "server message")

	if len(observed) != 1 {
		t.Errorf("expected 1 observed entry, got %d", len(observed))
	}
	if observed[0].Method != "GET" {
		t.Errorf("observed method = %q", observed[0].Method)
	}
}

func TestServerMessageJSON(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsoleBackend(&buf, "json")
	l := New(c)

	l.Infof("proxy", "listening on %s", ":8080")

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, buf.String())
	}
	if parsed["level"] != "info" {
		t.Errorf("level = %v", parsed["level"])
	}
	if parsed["component"] != "proxy" {
		t.Errorf("component = %v", parsed["component"])
	}
	if !strings.Contains(parsed["text"].(string), ":8080") {
		t.Errorf("text = %v", parsed["text"])
	}
}

func TestServerMessageHuman(t *testing.T) {
	var buf bytes.Buffer
	c := NewConsoleBackend(&buf, "human")
	l := New(c)

	l.Errorf("admin", "connection failed")

	line := buf.String()
	if !strings.Contains(line, "error") {
		t.Errorf("missing level in: %s", line)
	}
	if !strings.Contains(line, "admin") {
		t.Errorf("missing component in: %s", line)
	}
	if !strings.Contains(line, "connection failed") {
		t.Errorf("missing text in: %s", line)
	}
}
