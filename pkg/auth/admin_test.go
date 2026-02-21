package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func bcryptHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

func TestAdminAuthValid(t *testing.T) {
	aa := NewAdminAuth("admin", bcryptHash(t, "secret"))
	if !aa.Check("admin", "secret") {
		t.Error("expected valid credentials to pass")
	}
}

func TestAdminAuthWrongPassword(t *testing.T) {
	aa := NewAdminAuth("admin", bcryptHash(t, "secret"))
	if aa.Check("admin", "wrong") {
		t.Error("expected wrong password to fail")
	}
}

func TestAdminAuthWrongUser(t *testing.T) {
	aa := NewAdminAuth("admin", bcryptHash(t, "secret"))
	if aa.Check("wrong", "secret") {
		t.Error("expected wrong username to fail")
	}
}
