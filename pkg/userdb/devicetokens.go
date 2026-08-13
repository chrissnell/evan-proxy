package userdb

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
)

var ErrUnknownDevice = errors.New("unknown device")

// DeviceToken is a paired device as shown in the admin UI. The token itself is
// never stored or listed — only its SHA-256.
type DeviceToken struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

// CreateDeviceToken mints a random 32-byte token, stores only its SHA-256,
// and returns (plaintextToken, id). The plaintext is shown to the caller once.
func (d *DB) CreateDeviceToken(name string) (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	id := base64.RawURLEncoding.EncodeToString(sum[:8])
	if _, err := d.db.Exec(
		"INSERT INTO device_tokens (id, token_sha256, name) VALUES (?, ?, ?)",
		id, sum[:], name); err != nil {
		return "", "", fmt.Errorf("inserting device token: %w", err)
	}
	return token, id, nil
}

// ValidateDeviceToken returns the device name for a valid token and updates
// last_seen_at. Lookup is by the token's SHA-256 via the UNIQUE index; the
// token is a random 256-bit value, so hash equality is not guessable.
func (d *DB) ValidateDeviceToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	var name string
	err := d.db.QueryRow(
		"SELECT name FROM device_tokens WHERE token_sha256 = ?", sum[:]).Scan(&name)
	if err != nil {
		return "", false
	}
	d.db.Exec("UPDATE device_tokens SET last_seen_at = datetime('now') WHERE token_sha256 = ?", sum[:])
	return name, true
}

// ListDeviceTokens returns all paired devices, oldest first.
func (d *DB) ListDeviceTokens() ([]DeviceToken, error) {
	rows, err := d.db.Query(
		"SELECT id, name, created_at, last_seen_at FROM device_tokens ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("listing device tokens: %w", err)
	}
	defer rows.Close()

	var tokens []DeviceToken
	for rows.Next() {
		var t DeviceToken
		var lastSeen sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &lastSeen); err != nil {
			return nil, err
		}
		t.LastSeenAt = lastSeen.String
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// RevokeDeviceToken deletes a device token by id.
func (d *DB) RevokeDeviceToken(id string) error {
	res, err := d.db.Exec("DELETE FROM device_tokens WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("revoking device token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUnknownDevice
	}
	return nil
}
