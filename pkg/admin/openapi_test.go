package admin

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The iOS app generates its API client from its own copy of the spec, so the
// two files have to be hand-synced on every API change. Catch the drift here
// rather than at the next "why can't the app call this endpoint" moment.
func TestOpenAPISpecCopiesMatch(t *testing.T) {
	const canonical = "api/openapi.yaml"
	const iosCopy = "ios/Sources/EvanProxy/openapi.yaml"

	root := filepath.Join("..", "..")
	want, err := os.ReadFile(filepath.Join(root, canonical))
	if err != nil {
		t.Fatalf("reading %s: %v", canonical, err)
	}
	got, err := os.ReadFile(filepath.Join(root, iosCopy))
	if err != nil {
		t.Fatalf("reading %s: %v", iosCopy, err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s and %s have diverged — copy the canonical spec over the iOS one", canonical, iosCopy)
	}
}

// Endpoints the spec must document, so an API addition that the app needs
// cannot land without the operation the generator turns into a client method.
func TestOpenAPISpecDocumentsDowntimeEndpoints(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("reading spec: %v", err)
	}
	for _, path := range []string{
		"/api/users/downtime:",
		"/api/users/downtime-override:",
		"/api/users/downtime-now:",
	} {
		if !bytes.Contains(spec, []byte(path)) {
			t.Errorf("spec does not document %s", path)
		}
	}
}
