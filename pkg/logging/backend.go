package logging

import "time"

// Message wraps either an access log entry or a server message.
// Exactly one field is non-nil.
type Message struct {
	Access *Entry
	Server *ServerMessage
}

// ServerMessage represents a server info/error/warning log entry.
type ServerMessage struct {
	Timestamp time.Time `json:"ts"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Text      string    `json:"text"`
}

// Backend receives log messages. Implementations must be safe for concurrent use.
type Backend interface {
	Log(Message)
	Close() error
}
