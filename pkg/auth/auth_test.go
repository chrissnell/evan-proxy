package auth

import (
	"encoding/base64"
	"errors"
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
	user, err := store.Check(header)
	if err != nil || user != "alice" {
		t.Errorf("Check(%q) = (%q, %v), want (alice, nil)", header, user, err)
	}
}

func TestCheckWrongPassword(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"secret"}]}`)
	store, _ := LoadUsers(path)

	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	_, err := store.Check(header)
	if err == nil {
		t.Error("expected Check to fail for wrong password")
	}
	if !errors.Is(err, ErrWrongPassword) {
		t.Errorf("expected ErrWrongPassword, got: %v", err)
	}
}

func TestCheckUnknownUser(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"secret"}]}`)
	store, _ := LoadUsers(path)

	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("unknown:secret"))
	_, err := store.Check(header)
	if err == nil {
		t.Error("expected Check to fail for unknown user")
	}
	if !errors.Is(err, ErrUnknownUser) {
		t.Errorf("expected ErrUnknownUser, got: %v", err)
	}
}

func TestCheckInvalidHeader(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"secret"}]}`)
	store, _ := LoadUsers(path)

	cases := []struct {
		header string
		want   error
	}{
		{"", ErrNoCredentials},
		{"Bearer xyz", ErrMalformedAuth},
		{"Basic !!!invalid", ErrMalformedAuth},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), ErrMalformedAuth},
	}
	for _, tc := range cases {
		_, err := store.Check(tc.header)
		if err == nil {
			t.Errorf("expected Check(%q) to fail", tc.header)
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("Check(%q): got %v, want %v", tc.header, err, tc.want)
		}
	}
}

func TestCheckMultipleUsers(t *testing.T) {
	path := writeUsersFile(t, `{"users":[{"username":"alice","password":"pass1"},{"username":"bob","password":"pass2"}]}`)
	store, _ := LoadUsers(path)

	h1 := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:pass1"))
	h2 := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:pass2"))

	if user, err := store.Check(h1); err != nil || user != "alice" {
		t.Errorf("alice auth failed: %v", err)
	}
	if user, err := store.Check(h2); err != nil || user != "bob" {
		t.Errorf("bob auth failed: %v", err)
	}

	// Cross-check: alice's password shouldn't work for bob
	h3 := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:pass1"))
	if _, err := store.Check(h3); err == nil {
		t.Error("bob should not authenticate with alice's password")
	}
}
