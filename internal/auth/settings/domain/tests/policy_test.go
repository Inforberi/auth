package domain_test

import (
	"errors"
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestPolicyVerificationModes(t *testing.T) {
	for _, mode := range []settingsdomain.EmailVerification{settingsdomain.VerificationDisabled, settingsdomain.VerificationOptional, settingsdomain.VerificationRequired} {
		p := settingsdomain.Policy{PasswordEmailVerification: mode}
		if err := p.Validate(); err != nil {
			t.Fatal("admin-only profile must allow all public methods off", err)
		}
		p.Methods = settingsdomain.PublicMethods{Google: true, Telegram: true}
		p.Registration = settingsdomain.PublicRegistration{Enabled: false, Google: true, Telegram: true}
		if err := p.Validate(); err != nil {
			t.Fatal("disabled registration keeps method preferences", err)
		}
	}
	for _, mode := range []settingsdomain.EmailVerification{"", "enabled", "Required", " required "} {
		if err := (settingsdomain.Policy{PasswordEmailVerification: mode}).Validate(); !errors.Is(err, settingsdomain.ErrInvalidPolicy) {
			t.Fatal(mode, err)
		}
	}
}

func TestPolicyRequiresAvailableAdapters(t *testing.T) {
	for _, methods := range []settingsdomain.PublicMethods{{Password: true}, {EmailOTP: true}, {Google: true}, {Telegram: true}} {
		policy := settingsdomain.Policy{Methods: methods}
		if err := policy.RequireAvailable(settingsdomain.PublicMethods{}); !errors.Is(err, settingsdomain.ErrMethodNotReady) {
			t.Fatal("unavailable adapter admitted", methods, err)
		}
		if err := policy.RequireAvailable(methods); err != nil {
			t.Fatal("ready adapter rejected", methods, err)
		}
	}
	policy := settingsdomain.Policy{Registration: settingsdomain.PublicRegistration{Enabled: true, Google: true, Telegram: true}}
	if err := policy.RequireAvailable(settingsdomain.PublicMethods{}); err != nil {
		t.Fatal("disabled methods must preserve registration preferences", err)
	}
}
