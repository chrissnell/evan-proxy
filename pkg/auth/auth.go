package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// UserStore holds multiple proxy users for Basic auth validation.
type UserStore struct {
	users map[string][]byte
}

type usersFile struct {
	Users []userEntry `json:"users"`
}

type userEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoadUsers reads a JSON users file into a UserStore.
func LoadUsers(path string) (*UserStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading users file: %w", err)
	}

	var f usersFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing users file: %w", err)
	}

	if len(f.Users) == 0 {
		return nil, fmt.Errorf("users file contains no users")
	}

	store := &UserStore{users: make(map[string][]byte, len(f.Users))}
	for _, u := range f.Users {
		if u.Username == "" || u.Password == "" {
			return nil, fmt.Errorf("user entry with empty username or password")
		}
		store.users[u.Username] = []byte(u.Password)
	}
	return store, nil
}

// Check validates a Proxy-Authorization header value.
// Returns the username if valid, empty string if not.
func (us *UserStore) Check(proxyAuthHeader string) (string, bool) {
	user, pass, ok := parseBasicAuth(proxyAuthHeader)
	if !ok {
		return "", false
	}

	expected, exists := us.users[user]
	if !exists {
		// Constant-time compare against dummy to prevent timing leak
		subtle.ConstantTimeCompare([]byte(pass), []byte("dummy-password-for-timing"))
		return "", false
	}

	if subtle.ConstantTimeCompare([]byte(pass), expected) == 1 {
		return user, true
	}
	return "", false
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
