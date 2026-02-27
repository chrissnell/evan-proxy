package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// ConsoleBackend writes log messages to an io.Writer in human or JSON format.
type ConsoleBackend struct {
	mu     sync.Mutex
	w      io.Writer
	format string
	enc    *json.Encoder
}

func NewConsoleBackend(w io.Writer, format string) *ConsoleBackend {
	c := &ConsoleBackend{w: w, format: format}
	if format == "json" {
		c.enc = json.NewEncoder(w)
	}
	return c
}

func (c *ConsoleBackend) Log(msg Message) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if msg.Access != nil {
		c.logAccess(msg.Access)
	}
	if msg.Server != nil {
		c.logServer(msg.Server)
	}
}

func (c *ConsoleBackend) logAccess(e *Entry) {
	if c.format == "json" {
		c.enc.Encode(e)
		return
	}

	user := e.User
	if user == "" {
		user = "-"
	}
	uri := e.Host
	if e.URI != "" {
		uri = e.URI
	}
	event := e.Event
	if event == "" {
		event = "-"
	}
	errStr := ""
	if e.Error != "" {
		errStr = "  err=" + e.Error
	}
	fmt.Fprintf(c.w, "%s  %-5s  %-15s  %-7s  %-40s  %-16s  %d  %dms  %d/%d%s\n",
		e.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		event,
		e.ClientIP,
		e.Method,
		uri,
		user,
		e.Status,
		e.DurationMS,
		e.BytesRead,
		e.BytesWritten,
		errStr,
	)
}

func (c *ConsoleBackend) logServer(s *ServerMessage) {
	if c.format == "json" {
		c.enc.Encode(s)
		return
	}

	fmt.Fprintf(c.w, "%s  %-5s  %s: %s\n",
		s.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		s.Level,
		s.Component,
		s.Text,
	)
}

func (c *ConsoleBackend) Close() error { return nil }
