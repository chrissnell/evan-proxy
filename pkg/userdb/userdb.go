package userdb

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"evan-proxy/pkg/logging"
	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

var (
	ErrNoCredentials = errors.New("no credentials")
	ErrMalformedAuth = errors.New("malformed auth header")
	ErrUnknownUser   = errors.New("unknown user")
	ErrWrongPassword = errors.New("wrong password")
	ErrUserExists    = errors.New("user already exists")
)

// Argon2id parameters for new hashes. Existing hashes store their own
// params and are verified as-is; only newly created hashes use these.
const (
	argonTime    = 1
	argonMemory  = 16 * 1024 // 16MB — previous 64MB caused OOM on reconnection bursts
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16

	cacheTTL = 5 * time.Minute
)

// Limits concurrent argon2 operations to prevent memory spikes.
var argonSem = make(chan struct{}, 2)

type cachedAuth struct {
	passwordSHA256 [32]byte
	validUntil     time.Time
}

type UserInfo struct {
	Username    string `json:"username"`
	CreatedAt   string `json:"created_at"`
	DNSServer   string `json:"dns_server"`
	DNSProtocol string `json:"dns_protocol"`
	Port        int    `json:"port"`
	Enabled     bool   `json:"enabled"`
}

type DNSEntry struct {
	Server   string
	Protocol string
}

type DB struct {
	db     *sql.DB
	logger *logging.Logger
	mu     sync.RWMutex
	cache  map[string]cachedAuth

	dnsMu    sync.RWMutex
	dnsCache map[string]DNSEntry // username -> dns config
}

// Open opens (or creates) the SQLite user database at path.
func Open(path string, lg *logging.Logger) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening user database: %w", err)
	}

	// Single connection for SQLite
	sqlDB.SetMaxOpenConns(1)

	if _, err := sqlDB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			username     TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at   DATETIME NOT NULL DEFAULT (datetime('now'))
		)
	`); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("creating users table: %w", err)
	}

	udb := &DB{
		db:       sqlDB,
		logger:   lg,
		cache:    make(map[string]cachedAuth),
		dnsCache: make(map[string]DNSEntry),
	}

	if err := udb.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	if err := udb.loadDNSCache(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("loading DNS cache: %w", err)
	}

	return udb, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

// migrate adds columns introduced after the initial schema.
func (d *DB) migrate() error {
	rows, err := d.db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer rows.Close()

	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !cols["dns_server"] {
		if _, err := d.db.Exec("ALTER TABLE users ADD COLUMN dns_server TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("adding dns_server column: %w", err)
		}
		d.logger.Infof("userdb", "migrated — added dns_server column")
	}
	if !cols["dns_protocol"] {
		if _, err := d.db.Exec("ALTER TABLE users ADD COLUMN dns_protocol TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("adding dns_protocol column: %w", err)
		}
		d.logger.Infof("userdb", "migrated — added dns_protocol column")
	}
	if !cols["port"] {
		if _, err := d.db.Exec("ALTER TABLE users ADD COLUMN port INTEGER NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("adding port column: %w", err)
		}
		d.logger.Infof("userdb", "migrated — added port column")
	}
	if !cols["enabled"] {
		if _, err := d.db.Exec("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1"); err != nil {
			return fmt.Errorf("adding enabled column: %w", err)
		}
		d.logger.Infof("userdb", "migrated — added enabled column")
	}
	return nil
}

// loadDNSCache populates the in-memory DNS config cache from the database.
func (d *DB) loadDNSCache() error {
	rows, err := d.db.Query("SELECT username, dns_server, dns_protocol FROM users WHERE dns_server != ''")
	if err != nil {
		return err
	}
	defer rows.Close()

	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()

	for rows.Next() {
		var username, server, protocol string
		if err := rows.Scan(&username, &server, &protocol); err != nil {
			return err
		}
		d.dnsCache[username] = DNSEntry{Server: server, Protocol: protocol}
	}
	return rows.Err()
}

// GetDNS returns the per-user DNS config from the in-memory cache.
// Empty strings mean the user has no override (use global default).
func (d *DB) GetDNS(username string) (server, protocol string) {
	d.dnsMu.RLock()
	entry, ok := d.dnsCache[username]
	d.dnsMu.RUnlock()
	if !ok {
		return "", ""
	}
	return entry.Server, entry.Protocol
}

// UpdateDNS sets per-user DNS configuration.
// Pass empty strings to clear the override.
func (d *DB) UpdateDNS(username, server, protocol string) error {
	res, err := d.db.Exec("UPDATE users SET dns_server = ?, dns_protocol = ? WHERE username = ?",
		server, protocol, username)
	if err != nil {
		return fmt.Errorf("updating DNS config: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}

	d.dnsMu.Lock()
	if server == "" {
		delete(d.dnsCache, username)
	} else {
		d.dnsCache[username] = DNSEntry{Server: server, Protocol: protocol}
	}
	d.dnsMu.Unlock()

	return nil
}

// ErrNoPortAvailable is returned when all ports in the range are assigned.
var ErrNoPortAvailable = errors.New("no port available")

// Add creates a new user with an argon2id-hashed password and auto-assigns a port.
func (d *DB) Add(username, password string, portMin, portMax int) (int, error) {
	if username == "" || password == "" {
		return 0, fmt.Errorf("username and password must not be empty")
	}

	hash, err := hashPassword(password)
	if err != nil {
		return 0, fmt.Errorf("hashing password: %w", err)
	}

	port, err := d.nextAvailablePort(portMin, portMax)
	if err != nil {
		return 0, err
	}

	_, err = d.db.Exec("INSERT INTO users (username, password_hash, port) VALUES (?, ?, ?)", username, hash, port)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return 0, fmt.Errorf("%w: %q", ErrUserExists, username)
		}
		return 0, fmt.Errorf("inserting user: %w", err)
	}
	return port, nil
}

// nextAvailablePort finds the first unused port in [min, max].
func (d *DB) nextAvailablePort(min, max int) (int, error) {
	rows, err := d.db.Query("SELECT port FROM users WHERE port >= ? AND port <= ? ORDER BY port", min, max)
	if err != nil {
		return 0, fmt.Errorf("querying ports: %w", err)
	}
	defer rows.Close()

	used := make(map[int]bool)
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return 0, err
		}
		used[p] = true
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for p := min; p <= max; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, ErrNoPortAvailable
}

// SetEnabled enables or disables a user.
func (d *DB) SetEnabled(username string, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	res, err := d.db.Exec("UPDATE users SET enabled = ? WHERE username = ?", val, username)
	if err != nil {
		return fmt.Errorf("updating enabled: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	return nil
}

// IsEnabled returns whether a user is enabled. Returns false for unknown users.
func (d *DB) IsEnabled(username string) bool {
	var enabled int
	err := d.db.QueryRow("SELECT enabled FROM users WHERE username = ?", username).Scan(&enabled)
	if err != nil {
		return false
	}
	return enabled != 0
}

// Delete removes a user and invalidates their auth cache.
func (d *DB) Delete(username string) error {
	res, err := d.db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}

	d.mu.Lock()
	delete(d.cache, username)
	d.mu.Unlock()

	d.dnsMu.Lock()
	delete(d.dnsCache, username)
	d.dnsMu.Unlock()

	return nil
}

// ChangePassword updates a user's password and invalidates their auth cache.
func (d *DB) ChangePassword(username, newPassword string) error {
	if newPassword == "" {
		return fmt.Errorf("password must not be empty")
	}

	hash, err := hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	res, err := d.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", hash, username)
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}

	d.mu.Lock()
	delete(d.cache, username)
	d.mu.Unlock()

	return nil
}

// List returns all usernames and their creation times.
func (d *DB) List() ([]UserInfo, error) {
	rows, err := d.db.Query("SELECT username, created_at, dns_server, dns_protocol, port, enabled FROM users ORDER BY username")
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []UserInfo
	for rows.Next() {
		var u UserInfo
		var enabled int
		if err := rows.Scan(&u.Username, &u.CreatedAt, &u.DNSServer, &u.DNSProtocol, &u.Port, &enabled); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		u.Enabled = enabled != 0
		users = append(users, u)
	}
	return users, rows.Err()
}

// ListPorts returns a map of port → username for all users with assigned ports.
func (d *DB) ListPorts() (map[int]string, error) {
	rows, err := d.db.Query("SELECT port, username FROM users WHERE port > 0")
	if err != nil {
		return nil, fmt.Errorf("listing ports: %w", err)
	}
	defer rows.Close()

	ports := make(map[int]string)
	for rows.Next() {
		var port int
		var username string
		if err := rows.Scan(&port, &username); err != nil {
			return nil, fmt.Errorf("scanning port: %w", err)
		}
		ports[port] = username
	}
	return ports, rows.Err()
}

// UpdatePort assigns a dedicated proxy port to a user. Pass 0 to clear.
func (d *DB) UpdatePort(username string, port int) error {
	res, err := d.db.Exec("UPDATE users SET port = ? WHERE username = ?", port, username)
	if err != nil {
		return fmt.Errorf("updating port: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrUnknownUser, username)
	}
	return nil
}

// PortOwner returns the username that owns a given port, or "" if unassigned.
func (d *DB) PortOwner(port int) (string, error) {
	var username string
	err := d.db.QueryRow("SELECT username FROM users WHERE port = ?", port).Scan(&username)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("querying port owner: %w", err)
	}
	return username, nil
}

// Check validates a Proxy-Authorization header value.
// Uses an in-memory cache to avoid argon2id on every request.
func (d *DB) Check(proxyAuthHeader string) (string, error) {
	if proxyAuthHeader == "" {
		return "", ErrNoCredentials
	}

	user, pass, ok := parseBasicAuth(proxyAuthHeader)
	if !ok {
		return "", ErrMalformedAuth
	}

	passSHA := sha256.Sum256([]byte(pass))

	// Check cache first
	d.mu.RLock()
	cached, found := d.cache[user]
	d.mu.RUnlock()

	if found && time.Now().Before(cached.validUntil) {
		if subtle.ConstantTimeCompare(passSHA[:], cached.passwordSHA256[:]) == 1 {
			return user, nil
		}
		// Wrong password — don't return yet, fall through to DB check
		// (password might have changed and cache not yet invalidated... but we do invalidate on change)
		// Actually if cache exists but password doesn't match, it's wrong.
		return "", fmt.Errorf("%w: %q", ErrWrongPassword, user)
	}

	// Cache miss or expired — check against DB
	var storedHash string
	err := d.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", user).Scan(&storedHash)
	if err == sql.ErrNoRows {
		// Constant-time compare against dummy to prevent timing leak
		hashPassword("dummy-password-for-timing")
		return "", fmt.Errorf("%w: %q", ErrUnknownUser, user)
	}
	if err != nil {
		return "", fmt.Errorf("querying user: %w", err)
	}

	if !verifyPassword(pass, storedHash) {
		return "", fmt.Errorf("%w: %q", ErrWrongPassword, user)
	}

	// Re-hash with current params if the stored hash uses old (expensive) settings
	if needsRehash(storedHash) {
		if newHash, err := hashPassword(pass); err == nil {
			d.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", newHash, user)
		}
	}

	// Valid — populate cache
	d.mu.Lock()
	d.cache[user] = cachedAuth{
		passwordSHA256: passSHA,
		validUntil:     time.Now().Add(cacheTTL),
	}
	d.mu.Unlock()

	return user, nil
}

// hashPassword creates an argon2id hash with a random salt.
// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	argonSem <- struct{}{}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	<-argonSem

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// verifyPassword checks a password against an argon2id hash string.
func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var memory uint32
	var time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	argonSem <- struct{}{}
	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))
	<-argonSem
	return subtle.ConstantTimeCompare(hash, expectedHash) == 1
}

// needsRehash returns true if the stored hash uses different argon2 params
// than the current defaults (e.g. old 64MB hashes that should be migrated).
func needsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return true
	}
	expected := fmt.Sprintf("m=%d,t=%d,p=%d", argonMemory, argonTime, argonThreads)
	return parts[3] != expected
}

func parseBasicAuth(header string) (string, string, bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(header[6:])
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
