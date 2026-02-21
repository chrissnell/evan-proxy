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
	l := New(&buf, "json")

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
	l := New(&buf, "human")

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
	l := New(&buf, "human")

	l.Log(Entry{
		Timestamp: time.Now(), ClientIP: "10.0.0.1", Method: "CONNECT",
		Host: "example.com:443", Status: 407,
	})

	if !strings.Contains(buf.String(), "-") {
		t.Errorf("expected '-' for empty user in: %s", buf.String())
	}
}
