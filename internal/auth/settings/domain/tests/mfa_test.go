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

func TestMFAPolicyChangeOrder(t *testing.T) {
	before := settingsdomain.MFASnapshot{Version: 4, Policy: settingsdomain.MFAPolicy{Mode: settingsdomain.MFARequired}}
	for _, tc := range []struct {
		name           string
		version        int64
		next           settingsdomain.MFAMode
		ready, changed bool
		err            error
	}{
		{"version before no-op", 3, settingsdomain.MFARequired, false, false, settingsdomain.ErrPolicyConflict},
		{"no-op before readiness", 4, settingsdomain.MFARequired, false, false, nil},
		{"restricted change needs readiness", 4, settingsdomain.MFAAdministrators, false, false, settingsdomain.ErrMethodNotReady},
		{"optional without readiness", 4, settingsdomain.MFAOptional, false, true, nil},
		{"restricted change ready", 4, settingsdomain.MFAAdministrators, true, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := before.CheckChange(tc.version, settingsdomain.MFAPolicy{Mode: tc.next}, tc.ready)
			if changed != tc.changed || !errors.Is(err, tc.err) {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
		})
	}
	for _, tc := range []struct {
		version int64
		mode    settingsdomain.MFAMode
	}{
		{0, settingsdomain.MFAOptional}, {4, "invalid"}, {-1, "invalid"},
	} {
		if err := (settingsdomain.MFAPolicy{Mode: tc.mode}).ValidateChange(tc.version); !errors.Is(err, settingsdomain.ErrInvalidMFAPolicy) {
			t.Fatal("invalid transaction input accepted", err)
		}
	}
}
