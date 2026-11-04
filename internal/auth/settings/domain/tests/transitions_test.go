package domain_test

import (
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestRestrictsLogin(t *testing.T) {
	before := settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true}, Registration: settingsdomain.PublicRegistration{Enabled: true}, PasswordEmailVerification: settingsdomain.VerificationOptional}
	for _, tc := range []struct {
		name      string
		change    func(*settingsdomain.Policy)
		restricts bool
	}{
		{"no-op", func(*settingsdomain.Policy) {}, false},
		{"password off", func(p *settingsdomain.Policy) { p.Methods.Password = false }, true},
		{"otp off", func(p *settingsdomain.Policy) { p.Methods.EmailOTP = false }, true},
		{"google off", func(p *settingsdomain.Policy) { p.Methods.Google = false }, true},
		{"telegram off", func(p *settingsdomain.Policy) { p.Methods.Telegram = false }, true},
		{"verified password", func(p *settingsdomain.Policy) { p.PasswordEmailVerification = settingsdomain.VerificationRequired }, true},
		{"verification disabled", func(p *settingsdomain.Policy) { p.PasswordEmailVerification = settingsdomain.VerificationDisabled }, false},
		{"registration closed", func(p *settingsdomain.Policy) { p.Registration.Enabled = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := before
			tc.change(&after)
			if after.RestrictsLogin(before) != tc.restricts {
				t.Fatal("incorrect transition classification")
			}
		})
	}
	closed := settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationRequired}
	opened := closed
	opened.Methods.Password = true
	if opened.RestrictsLogin(closed) {
		t.Fatal("opening a method must remain available for recovery")
	}
	if closed.RestrictsLogin(closed) {
		t.Fatal("closed no-op is not a restriction")
	}
}
