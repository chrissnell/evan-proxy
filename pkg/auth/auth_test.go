package auth

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func writeUsersFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadUsersValid(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"pass1"},{"username":"bob","password":"pass2"}]}`)
	store, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers: %v", err)
	}
	if len(store.users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(store.users))
	}
}

func TestLoadUsersEmpty(t *testing.T) {
	path := writeUsersFile(t, `{"users":[]}`)
	_, err := LoadUsers(path)
	if err == nil {
		t.Fatal("expected error for empty users list")
	}
}

func TestLoadUsersMissingField(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":""}]}`)
	_, err := LoadUsers(path)
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestCheckValid(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"secret"}]}`)
	store, _ := LoadUsers(path)

	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	user, ok := store.Check(header)
	if !ok || user != "alice" {
		t.Errorf("Check(%q) = (%q, %v), want (alice, true)", header, user, ok)
	}
}

func TestCheckWrongPassword(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"secret"}]}`)
	store, _ := LoadUsers(path)

	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	_, ok := store.Check(header)
	if ok {
		t.Error("expected Check to fail for wrong password")
	}
}

func TestCheckUnknownUser(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"secret"}]}`)
	store, _ := LoadUsers(path)

	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("unknown:secret"))
	_, ok := store.Check(header)
	if ok {
		t.Error("expected Check to fail for unknown user")
	}
}

func TestCheckInvalidHeader(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"secret"}]}`)
	store, _ := LoadUsers(path)

	cases := []string{"", "Bearer xyz", "Basic !!!invalid", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))}
	for _, h := range cases {
		if _, ok := store.Check(h); ok {
			t.Errorf("expected Check(%q) to fail", h)
		}
	}
}

func TestCheckMultipleUsers(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"pass1"},{"username":"bob","password":"pass2"}]}`)
	store, _ := LoadUsers(path)

	h1 := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:pass1"))
	h2 := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:pass2"))

	if user, ok := store.Check(h1); !ok || user != "alice" {
		t.Errorf("alice auth failed")
	}
	if user, ok := store.Check(h2); !ok || user != "bob" {
		t.Errorf("bob auth failed")
	}

	// Cross-check: alice's password shouldn't work for bob
	h3 := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:pass1"))
	if _, ok := store.Check(h3); ok {
		t.Error("bob should not authenticate with alice's password")
	}
}
