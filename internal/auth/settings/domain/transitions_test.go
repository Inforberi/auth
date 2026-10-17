package domain

import "testing"

func TestRestrictsLogin(t *testing.T) {
	before := Policy{Methods: PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true}, Registration: PublicRegistration{Enabled: true}, PasswordEmailVerification: VerificationOptional}
	for _, tc := range []struct {
		name      string
		change    func(*Policy)
		restricts bool
	}{
		{"no-op", func(*Policy) {}, false},
		{"password off", func(p *Policy) { p.Methods.Password = false }, true},
		{"otp off", func(p *Policy) { p.Methods.EmailOTP = false }, true},
		{"google off", func(p *Policy) { p.Methods.Google = false }, true},
		{"telegram off", func(p *Policy) { p.Methods.Telegram = false }, true},
		{"verified password", func(p *Policy) { p.PasswordEmailVerification = VerificationRequired }, true},
		{"verification disabled", func(p *Policy) { p.PasswordEmailVerification = VerificationDisabled }, false},
		{"registration closed", func(p *Policy) { p.Registration.Enabled = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := before
			tc.change(&after)
			if after.RestrictsLogin(before) != tc.restricts {
				t.Fatal("incorrect transition classification")
			}
		})
	}
	closed := Policy{PasswordEmailVerification: VerificationRequired}
	opened := closed
	opened.Methods.Password = true
	if opened.RestrictsLogin(closed) {
		t.Fatal("opening a method must remain available for recovery")
	}
	if closed.RestrictsLogin(closed) {
		t.Fatal("closed no-op is not a restriction")
	}
}
