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

func TestMFAPolicyStrengthening(t *testing.T) {
	modes := []MFAMode{MFAOptional, MFAAdministrators, MFARequired}
	for from, previous := range modes {
		for to, next := range modes {
			if got := (MFAPolicy{Mode: next}).Strengthens(MFAPolicy{Mode: previous}); got != (to > from) {
				t.Fatal(previous, next, got)
			}
		}
	}
}
