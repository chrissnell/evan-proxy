package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

type Entry struct {
	Timestamp    time.Time `json:"ts"`
	Event        string    `json:"event"`          // "open", "close", or "" for non-tunnel
	ClientIP     string    `json:"client_ip"`
	Method       string    `json:"method"`
	Host         string    `json:"host"`
	URI          string    `json:"uri,omitempty"`
	User         string    `json:"user,omitempty"`
	Status       int       `json:"status"`
	DurationMS   int64     `json:"duration_ms"`
	BytesRead    int64     `json:"bytes_read"`
	BytesWritten int64     `json:"bytes_written"`
}

type Logger struct {
	mu        sync.Mutex
	w         io.Writer
	format    string
	enc       *json.Encoder
	observers []func(Entry)
}

// AddObserver registers a callback invoked on each Log call.
// Observers run under the logger mutex and must not block.
func (l *Logger) AddObserver(fn func(Entry)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.observers = append(l.observers, fn)
}

func New(w io.Writer, format string) *Logger {
	l := &Logger{w: w, format: format}
	if format == "json" {
		l.enc = json.NewEncoder(w)
	}
	return l
}

func (l *Logger) Log(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.format == "json" {
		l.enc.Encode(e)
	} else {
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
		fmt.Fprintf(l.w, "%s  %-5s  %-15s  %-7s  %-40s  %-16s  %d  %dms  %d/%d\n",
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
		)
	}

	for _, fn := range l.observers {
		fn(e)
	}
}
