package domain_test

import (
	"errors"
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestPublicMethodPolicy(t *testing.T) {
	policy := settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true}, Registration: settingsdomain.PublicRegistration{Enabled: true, Google: true, Telegram: false}, PasswordEmailVerification: settingsdomain.VerificationOptional}
	for _, tc := range []struct {
		method       string
		registration bool
		want         error
	}{
		{"password", false, nil}, {"password", true, nil}, {"emailotp", true, settingsdomain.ErrRegistrationDisabled}, {"google", true, nil}, {"telegram", false, nil}, {"telegram", true, settingsdomain.ErrRegistrationDisabled}, {"unknown", false, settingsdomain.ErrMethodDisabled},
	} {
		if err := policy.RequireMethod(tc.method, tc.registration); !errors.Is(err, tc.want) {
			t.Fatal(tc, err)
		}
	}
	policy.Registration.Enabled = false
	for _, method := range []string{"password", "google", "telegram"} {
		if policy.RequireMethod(method, false) != nil || !errors.Is(policy.RequireMethod(method, true), settingsdomain.ErrRegistrationDisabled) {
			t.Fatal("registration switch disabled login", method)
		}
	}
	policy.Methods = settingsdomain.PublicMethods{}
	for _, method := range []string{"password", "emailotp", "google", "telegram"} {
		if !errors.Is(policy.RequireMethod(method, false), settingsdomain.ErrMethodDisabled) {
			t.Fatal(method)
		}
	}
}

func TestPrimaryMethodMapping(t *testing.T) {
	for _, tc := range []struct{ method, issuer, want string }{
		{"password", "", "password"}, {"emailotp", "", "emailotp"}, {"oidc", "https://accounts.google.com", "google"}, {"oidc", "https://oauth.telegram.org", "telegram"}, {"oidc", "https://ACCOUNTS.google.com", ""}, {"password", "https://accounts.google.com", ""}, {"oidc", "https://foreign.example", ""},
	} {
		if got := settingsdomain.PrimaryMethod(tc.method, tc.issuer); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
