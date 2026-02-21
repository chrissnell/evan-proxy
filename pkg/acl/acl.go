package acl

// ACL decides whether a request to a given host should proceed.
type ACL interface {
	// Allow returns true if the request to host (in "hostname:port" format) should proceed.
	Allow(host string) bool
}

// AllowAll permits all destinations.
type AllowAll struct{}

func (AllowAll) Allow(string) bool { return true }
