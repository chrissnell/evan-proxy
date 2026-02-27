package logging

import (
	"fmt"
	"os"
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
	Error        string    `json:"error,omitempty"`
	Status       int       `json:"status"`
	DurationMS   int64     `json:"duration_ms"`
	BytesRead    int64     `json:"bytes_read"`
	BytesWritten int64     `json:"bytes_written"`
}

type Logger struct {
	mu        sync.Mutex
	backends  []Backend
	observers []func(Entry)
}

// New creates a Logger that dispatches to all provided backends.
func New(backends ...Backend) *Logger {
	return &Logger{backends: backends}
}

// AddObserver registers a callback invoked on each access log entry.
// Observers run under the logger mutex and must not block.
func (l *Logger) AddObserver(fn func(Entry)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.observers = append(l.observers, fn)
}

// Log dispatches an access log entry to all backends and observers.
func (l *Logger) Log(e Entry) {
	msg := Message{Access: &e}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, b := range l.backends {
		b.Log(msg)
	}
	for _, fn := range l.observers {
		fn(e)
	}
}

// ServerLog dispatches a server message to all backends.
func (l *Logger) ServerLog(level, component, text string) {
	msg := Message{Server: &ServerMessage{
		Timestamp: time.Now(),
		Level:     level,
		Component: component,
		Text:      text,
	}}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, b := range l.backends {
		b.Log(msg)
	}
}

func (l *Logger) Infof(component, format string, args ...any) {
	l.ServerLog("info", component, fmt.Sprintf(format, args...))
}

func (l *Logger) Errorf(component, format string, args ...any) {
	l.ServerLog("error", component, fmt.Sprintf(format, args...))
}

func (l *Logger) Fatalf(component, format string, args ...any) {
	l.ServerLog("error", component, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// Close closes all backends.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, b := range l.backends {
		b.Close()
	}
}
