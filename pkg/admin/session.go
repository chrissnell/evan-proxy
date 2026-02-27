package admin

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"evan-proxy/pkg/logging"
	_ "modernc.org/sqlite"
)

const sessionCookie = "evan-proxy-session"

// SessionStore manages admin sessions in SQLite.
type SessionStore struct {
	db     *sql.DB
	ttl    time.Duration
	stop   chan struct{}
	logger *logging.Logger
}

func NewSessionStore(dbPath string, ttl time.Duration, lg *logging.Logger) (*SessionStore, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening session database: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS admin_sessions (
			token      TEXT PRIMARY KEY,
			expires_at DATETIME NOT NULL
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating sessions table: %w", err)
	}

	ss := &SessionStore{db: db, ttl: ttl, stop: make(chan struct{}), logger: lg}
	go ss.cleanup()
	return ss, nil
}

// Create generates a new session token.
func (ss *SessionStore) Create() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	expiresAt := time.Now().Add(ss.ttl)
	ss.db.Exec(`INSERT INTO admin_sessions (token, expires_at) VALUES (?, ?)`, token, expiresAt)
	return token
}

// Validate checks if a session token is valid and renews its expiration.
func (ss *SessionStore) Validate(token string) bool {
	var expiresAt time.Time
	err := ss.db.QueryRow(`SELECT expires_at FROM admin_sessions WHERE token = ?`, token).Scan(&expiresAt)
	if err != nil {
		return false
	}
	if time.Now().After(expiresAt) {
		ss.db.Exec(`DELETE FROM admin_sessions WHERE token = ?`, token)
		return false
	}
	// Sliding expiration
	newExpiry := time.Now().Add(ss.ttl)
	ss.db.Exec(`UPDATE admin_sessions SET expires_at = ? WHERE token = ?`, newExpiry, token)
	return true
}

// Delete removes a session.
func (ss *SessionStore) Delete(token string) {
	ss.db.Exec(`DELETE FROM admin_sessions WHERE token = ?`, token)
}

// Stop terminates the background cleanup goroutine and closes the database.
func (ss *SessionStore) Stop() {
	close(ss.stop)
	ss.db.Close()
}

func (ss *SessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			result, err := ss.db.Exec(`DELETE FROM admin_sessions WHERE expires_at < ?`, time.Now())
			if err == nil {
				if n, _ := result.RowsAffected(); n > 0 {
					ss.logger.Infof("admin", "cleaned up %d expired admin sessions", n)
				}
			}
		case <-ss.stop:
			return
		}
	}
}
