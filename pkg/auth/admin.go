package auth

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// AdminAuth validates admin credentials using bcrypt.
type AdminAuth struct {
	user       string
	bcryptHash []byte
}

func NewAdminAuth(user, bcryptHash string) *AdminAuth {
	return &AdminAuth{
		user:       user,
		bcryptHash: []byte(bcryptHash),
	}
}

// Check validates plaintext credentials against the stored bcrypt hash.
// Returns nil on success, or an error describing the failure.
func (aa *AdminAuth) Check(user, password string) error {
	// Constant-time username comparison
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(aa.user)) == 1
	// Always check password to prevent timing attacks
	passErr := bcrypt.CompareHashAndPassword(aa.bcryptHash, []byte(password))
	if !userMatch {
		return fmt.Errorf("%w: %q", ErrUnknownUser, user)
	}
	if passErr != nil {
		return ErrWrongPassword
	}
	return nil
}
