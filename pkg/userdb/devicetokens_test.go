package userdb

import (
	"errors"
	"testing"
)

func TestDeviceTokens_CreateValidateRevoke(t *testing.T) {
	d := openTestDB(t)
	tok, id, err := d.CreateDeviceToken("Chris's iPhone")
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" || id == "" {
		t.Fatal("empty token/id")
	}

	name, ok := d.ValidateDeviceToken(tok)
	if !ok || name != "Chris's iPhone" {
		t.Fatalf("validate failed: %q %v", name, ok)
	}

	if _, ok := d.ValidateDeviceToken("bogus"); ok {
		t.Fatal("bogus token validated")
	}

	if err := d.RevokeDeviceToken(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.ValidateDeviceToken(tok); ok {
		t.Fatal("revoked token still valid")
	}
}

func TestDeviceTokens_List(t *testing.T) {
	d := openTestDB(t)

	list, err := d.ListDeviceTokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("want empty list, got %d", len(list))
	}

	tok, id, err := d.CreateDeviceToken("phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.CreateDeviceToken("tablet"); err != nil {
		t.Fatal(err)
	}

	list, err = d.ListDeviceTokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 devices, got %d", len(list))
	}
	for _, dt := range list {
		if dt.ID == "" || dt.Name == "" || dt.CreatedAt == "" {
			t.Fatalf("incomplete device entry: %+v", dt)
		}
		if dt.LastSeenAt != "" {
			t.Fatalf("last_seen_at should be empty before first use: %+v", dt)
		}
	}

	// Validation stamps last_seen_at.
	if _, ok := d.ValidateDeviceToken(tok); !ok {
		t.Fatal("validate failed")
	}
	list, err = d.ListDeviceTokens()
	if err != nil {
		t.Fatal(err)
	}
	for _, dt := range list {
		if dt.ID == id && dt.LastSeenAt == "" {
			t.Fatal("last_seen_at not updated after validation")
		}
	}
}

func TestDeviceTokens_RevokeUnknown(t *testing.T) {
	d := openTestDB(t)
	if err := d.RevokeDeviceToken("nope"); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("want ErrUnknownDevice, got %v", err)
	}
}
