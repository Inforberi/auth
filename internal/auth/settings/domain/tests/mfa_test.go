package domain_test

import (
	"errors"
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestMFAPolicyModes(t *testing.T) {
	for _, mode := range []settingsdomain.MFAMode{settingsdomain.MFAOptional, settingsdomain.MFAAdministrators, settingsdomain.MFARequired} {
		if err := (settingsdomain.MFAPolicy{Mode: mode}).Validate(); err != nil {
			t.Fatal(mode, err)
		}
	}
	for _, mode := range []settingsdomain.MFAMode{"", "disabled", "REQUIRED", " optional ", "roles"} {
		if err := (settingsdomain.MFAPolicy{Mode: mode}).Validate(); !errors.Is(err, settingsdomain.ErrInvalidMFAPolicy) {
			t.Fatal("unknown mode accepted", mode, err)
		}
	}
}

func TestMFAPolicyStrengthening(t *testing.T) {
	modes := []settingsdomain.MFAMode{settingsdomain.MFAOptional, settingsdomain.MFAAdministrators, settingsdomain.MFARequired}
	for from, previous := range modes {
		for to, next := range modes {
			if got := (settingsdomain.MFAPolicy{Mode: next}).Strengthens(settingsdomain.MFAPolicy{Mode: previous}); got != (to > from) {
				t.Fatal(previous, next, got)
			}
		}
	}
}
