package userdb

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func makeBasicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestAddAndList(t *testing.T) {
	db := openTestDB(t)

	if err := db.Add("alice", "pass1"); err != nil {
		t.Fatal(err)
	}
	if err := db.Add("bob", "pass2"); err != nil {
		t.Fatal(err)
	}

	users, err := db.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0].Username != "alice" || users[1].Username != "bob" {
		t.Errorf("unexpected users: %+v", users)
	}
}

func TestAddDuplicate(t *testing.T) {
	db := openTestDB(t)

	if err := db.Add("alice", "pass1"); err != nil {
		t.Fatal(err)
	}
	err := db.Add("alice", "pass2")
	if !errors.Is(err, ErrUserExists) {
		t.Errorf("expected ErrUserExists, got: %v", err)
	}
}

func TestDelete(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "pass1")

	if err := db.Delete("alice"); err != nil {
		t.Fatal(err)
	}

	users, _ := db.List()
	if len(users) != 0 {
		t.Errorf("expected 0 users after delete, got %d", len(users))
	}
}

func TestDeleteUnknown(t *testing.T) {
	db := openTestDB(t)

	err := db.Delete("nobody")
	if !errors.Is(err, ErrUnknownUser) {
		t.Errorf("expected ErrUnknownUser, got: %v", err)
	}
}

func TestCheckValid(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "secret")

	user, err := db.Check(makeBasicAuth("alice", "secret"))
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if user != "alice" {
		t.Errorf("expected alice, got %q", user)
	}
}

func TestCheckWrongPassword(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "secret")

	_, err := db.Check(makeBasicAuth("alice", "wrong"))
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("expected ErrWrongPassword, got: %v", err)
	}
}

func TestCheckUnknownUser(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "secret")

	_, err := db.Check(makeBasicAuth("unknown", "secret"))
	if !errors.Is(err, ErrUnknownUser) {
		t.Errorf("expected ErrUnknownUser, got: %v", err)
	}
}

func TestCheckNoCredentials(t *testing.T) {
	db := openTestDB(t)

	_, err := db.Check("")
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("expected ErrNoCredentials, got: %v", err)
	}
}

func TestCheckMalformedAuth(t *testing.T) {
	db := openTestDB(t)

	cases := []string{
		"Bearer xyz",
		"Basic !!!invalid",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")),
	}
	for _, h := range cases {
		_, err := db.Check(h)
		if !errors.Is(err, ErrMalformedAuth) {
			t.Errorf("Check(%q): expected ErrMalformedAuth, got: %v", h, err)
		}
	}
}

func TestCheckCacheHit(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "secret")

	// First call populates cache
	db.Check(makeBasicAuth("alice", "secret"))

	// Second call should hit cache (no way to observe directly, but should succeed)
	user, err := db.Check(makeBasicAuth("alice", "secret"))
	if err != nil || user != "alice" {
		t.Errorf("cached Check failed: user=%q err=%v", user, err)
	}
}

func TestCheckCacheInvalidatedOnDelete(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "secret")

	// Populate cache
	db.Check(makeBasicAuth("alice", "secret"))

	// Delete user
	db.Delete("alice")

	// Should fail now
	_, err := db.Check(makeBasicAuth("alice", "secret"))
	if !errors.Is(err, ErrUnknownUser) {
		t.Errorf("expected ErrUnknownUser after delete, got: %v", err)
	}
}

func TestCheckCacheInvalidatedOnPasswordChange(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "secret")

	// Populate cache
	db.Check(makeBasicAuth("alice", "secret"))

	// Change password
	db.ChangePassword("alice", "newsecret")

	// Old password should fail (cache was invalidated)
	_, err := db.Check(makeBasicAuth("alice", "secret"))
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("expected ErrWrongPassword after password change, got: %v", err)
	}

	// New password should work
	user, err := db.Check(makeBasicAuth("alice", "newsecret"))
	if err != nil || user != "alice" {
		t.Errorf("new password Check failed: user=%q err=%v", user, err)
	}
}

func TestChangePassword(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "old")

	if err := db.ChangePassword("alice", "new"); err != nil {
		t.Fatal(err)
	}

	// Old password fails
	_, err := db.Check(makeBasicAuth("alice", "old"))
	if err == nil {
		t.Error("old password should fail")
	}

	// New password works
	user, err := db.Check(makeBasicAuth("alice", "new"))
	if err != nil || user != "alice" {
		t.Errorf("new password failed: %v", err)
	}
}

func TestChangePasswordUnknown(t *testing.T) {
	db := openTestDB(t)

	err := db.ChangePassword("nobody", "pass")
	if !errors.Is(err, ErrUnknownUser) {
		t.Errorf("expected ErrUnknownUser, got: %v", err)
	}
}

func TestSeedFromFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedPath := filepath.Join(dir, "users.json")

	// Write seed file
	seed := `{"users":[{"username":"alice","password":"pass1"},{"username":"bob","password":"pass2"}]}`
	if err := writeFile(seedPath, []byte(seed)); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dbPath, seedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	users, _ := db.List()
	if len(users) != 2 {
		t.Fatalf("expected 2 seeded users, got %d", len(users))
	}

	// Seeded users should be authenticable
	user, err := db.Check(makeBasicAuth("alice", "pass1"))
	if err != nil || user != "alice" {
		t.Errorf("seeded user auth failed: %v", err)
	}
}

func TestSeedSkippedIfDBHasUsers(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedPath := filepath.Join(dir, "users.json")

	seed := `{"users":[{"username":"seed","password":"pass"}]}`
	writeFile(seedPath, []byte(seed))

	// Create DB with existing user
	db1, _ := Open(dbPath, "")
	db1.Add("existing", "pass")
	db1.Close()

	// Re-open with seed — should NOT import
	db2, _ := Open(dbPath, seedPath)
	defer db2.Close()

	users, _ := db2.List()
	if len(users) != 1 || users[0].Username != "existing" {
		t.Errorf("seed should be skipped when DB has users, got: %+v", users)
	}
}

func TestHashAndVerify(t *testing.T) {
	hash, err := hashPassword("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword("testpass", hash) {
		t.Error("verifyPassword should return true for correct password")
	}
	if verifyPassword("wrong", hash) {
		t.Error("verifyPassword should return false for wrong password")
	}
}

func TestMigrationAddsColumns(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create DB with old schema (no dns columns).
	sqlDB, err := openRawDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.Exec(`CREATE TABLE users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT (datetime('now'))
	)`)
	sqlDB.Exec("INSERT INTO users (username, password_hash) VALUES ('alice', 'hash')")
	sqlDB.Close()

	// Open with migration.
	db, err := Open(dbPath, "")
	if err != nil {
		t.Fatalf("Open after migration: %v", err)
	}
	defer db.Close()

	users, err := db.List()
	if err != nil {
		t.Fatalf("List after migration: %v", err)
	}
	if len(users) != 1 || users[0].Username != "alice" {
		t.Errorf("unexpected users after migration: %+v", users)
	}
	// DNS fields should be empty defaults.
	if users[0].DNSServer != "" || users[0].DNSProtocol != "" {
		t.Errorf("expected empty DNS fields, got server=%q protocol=%q",
			users[0].DNSServer, users[0].DNSProtocol)
	}
}

func TestUpdateDNS(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "pass")

	if err := db.UpdateDNS("alice", "1.1.1.1:853", "tls"); err != nil {
		t.Fatal(err)
	}

	server, proto := db.GetDNS("alice")
	if server != "1.1.1.1:853" || proto != "tls" {
		t.Errorf("GetDNS = (%q, %q), want (1.1.1.1:853, tls)", server, proto)
	}

	// Verify persisted in DB via List.
	users, _ := db.List()
	if users[0].DNSServer != "1.1.1.1:853" || users[0].DNSProtocol != "tls" {
		t.Errorf("List DNS = (%q, %q), want (1.1.1.1:853, tls)",
			users[0].DNSServer, users[0].DNSProtocol)
	}
}

func TestUpdateDNSClear(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "pass")
	db.UpdateDNS("alice", "1.1.1.1:853", "tls")

	// Clear DNS config.
	if err := db.UpdateDNS("alice", "", ""); err != nil {
		t.Fatal(err)
	}

	server, proto := db.GetDNS("alice")
	if server != "" || proto != "" {
		t.Errorf("GetDNS after clear = (%q, %q), want empty", server, proto)
	}
}

func TestUpdateDNSUnknownUser(t *testing.T) {
	db := openTestDB(t)

	err := db.UpdateDNS("nobody", "1.1.1.1:53", "plain")
	if !errors.Is(err, ErrUnknownUser) {
		t.Errorf("expected ErrUnknownUser, got: %v", err)
	}
}

func TestGetDNSDefault(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "pass")

	server, proto := db.GetDNS("alice")
	if server != "" || proto != "" {
		t.Errorf("expected empty DNS for new user, got (%q, %q)", server, proto)
	}
}

func TestDeleteClearsDNSCache(t *testing.T) {
	db := openTestDB(t)
	db.Add("alice", "pass")
	db.UpdateDNS("alice", "1.1.1.1:853", "tls")

	db.Delete("alice")

	server, proto := db.GetDNS("alice")
	if server != "" || proto != "" {
		t.Errorf("GetDNS after delete = (%q, %q), want empty", server, proto)
	}
}

func TestDNSCacheLoadedOnOpen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create DB and set DNS config.
	db1, _ := Open(dbPath, "")
	db1.Add("alice", "pass")
	db1.UpdateDNS("alice", "https://1.1.1.1/dns-query", "https")
	db1.Close()

	// Re-open — cache should be populated.
	db2, err := Open(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	server, proto := db2.GetDNS("alice")
	if server != "https://1.1.1.1/dns-query" || proto != "https" {
		t.Errorf("GetDNS after reopen = (%q, %q), want (https://1.1.1.1/dns-query, https)",
			server, proto)
	}
}

// openRawDB opens a raw sql.DB for test setup (no migration).
func openRawDB(path string) (*sql.DB, error) {
	return sql.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
}

func writeFile(path string, data []byte) error {
	return writeFileWithPerm(path, data, 0600)
}

func writeFileWithPerm(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
