package auth

import (
	"crypto/subtle"

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
func (aa *AdminAuth) Check(user, password string) bool {
	// Constant-time username comparison
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(aa.user)) == 1
	// Always check password to prevent timing attacks
	passErr := bcrypt.CompareHashAndPassword(aa.bcryptHash, []byte(password))
	return userMatch && passErr == nil
}
