package domain

import (
	"errors"
	"testing"
)

func TestMFAPolicyModes(t *testing.T) {
	for _, mode := range []MFAMode{MFAOptional, MFAAdministrators, MFARequired} {
		if err := (MFAPolicy{Mode: mode}).Validate(); err != nil {
			t.Fatal(mode, err)
		}
	}
	for _, mode := range []MFAMode{"", "disabled", "REQUIRED", " optional ", "roles"} {
		if err := (MFAPolicy{Mode: mode}).Validate(); !errors.Is(err, ErrInvalidMFAPolicy) {
			t.Fatal("unknown mode accepted", mode, err)
		}
	}
}
