package domain

import "testing"

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
		if ValidProviderClientID(tc.name, tc.id) != tc.valid {
			t.Fatal(tc)
		}
	}
}
