package domain

import (
	"errors"
	"testing"
)

func TestEmailOwnershipKey(t *testing.T) {
	email, err := NewEmail("  User@Example.COM  ")
	if err != nil || email.String() != "user@example.com" {
		t.Fatalf("normalization failed: %v", err)
	}
	for _, raw := range []string{"Name <user@example.com>", "<user@example.com>", "user@example.com (Name)", "bad", "user@example.com\nBcc: x@example.com"} {
		if _, err := NewEmail(raw); !errors.Is(err, ErrEmailInvalid) {
			t.Errorf("accepted non-address %q", raw)
		}
	}
}
