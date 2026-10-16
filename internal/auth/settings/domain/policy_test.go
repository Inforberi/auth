package domain

import (
	"errors"
	"testing"
)

func TestPolicyVerificationModes(t *testing.T) {
	for _, mode := range []EmailVerification{VerificationDisabled, VerificationOptional, VerificationRequired} {
		p := Policy{PasswordEmailVerification: mode}
		if err := p.Validate(); err != nil {
			t.Fatal("admin-only profile must allow all public methods off", err)
		}
		p.Methods = PublicMethods{Google: true, Telegram: true}
		p.Registration = PublicRegistration{Enabled: false, Google: true, Telegram: true}
		if err := p.Validate(); err != nil {
			t.Fatal("disabled registration keeps method preferences", err)
		}
	}
	for _, mode := range []EmailVerification{"", "enabled", "Required", " required "} {
		if err := (Policy{PasswordEmailVerification: mode}).Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal(mode, err)
		}
	}
}

func TestPolicyRequiresAvailableAdapters(t *testing.T) {
	for _, methods := range []PublicMethods{{Password: true}, {EmailOTP: true}, {Google: true}, {Telegram: true}} {
		policy := Policy{Methods: methods}
		if err := policy.RequireAvailable(PublicMethods{}); !errors.Is(err, ErrMethodNotReady) {
			t.Fatal("unavailable adapter admitted", methods, err)
		}
		if err := policy.RequireAvailable(methods); err != nil {
			t.Fatal("ready adapter rejected", methods, err)
		}
	}
	policy := Policy{Registration: PublicRegistration{Enabled: true, Google: true, Telegram: true}}
	if err := policy.RequireAvailable(PublicMethods{}); err != nil {
		t.Fatal("disabled methods must preserve registration preferences", err)
	}
}
