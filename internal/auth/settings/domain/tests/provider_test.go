package domain_test

import (
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestFixedProviderCredentialRules(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		valid    bool
	}{
		{"google", "fixture.apps.googleusercontent.com", true},
		{"telegram", "123", true},
		{"google", "fixture", false},
		{"telegram", "00123", false},
		{"telegram", "0", false},
		{"google", "", false},
		{"unknown", "123", false},
	} {
		if settingsdomain.ValidProviderClientID(tc.name, tc.id) != tc.valid {
			t.Fatal(tc)
		}
	}
}
