package acl

import "testing"

func TestAllowAll(t *testing.T) {
	a := AllowAll{}
	cases := []string{"example.com:443", "evil.com:80", "localhost:8080", ""}
	for _, host := range cases {
		if !a.Allow(host) {
			t.Errorf("AllowAll.Allow(%q) = false, want true", host)
		}
	}
}
