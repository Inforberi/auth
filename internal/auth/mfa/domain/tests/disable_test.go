package domain_test

import (
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func TestDisableTOTPPolicy(t *testing.T) {
	cases := []struct {
		name    string
		state   domain.DisableState
		allowed bool
	}{
		{"optional without alternatives", domain.DisableState{}, true},
		{"required last factor", domain.DisableState{Required: true}, false},
		{"required usable email", domain.DisableState{Required: true, Email: true, UsableEmail: true}, true},
		{"required usable telegram", domain.DisableState{Required: true, Telegram: true, UsableTelegram: true}, true},
		{"admin cannot retain weak email", domain.DisableState{Administrative: true, Email: true, UsableEmail: true}, false},
		{"admin cannot retain weak telegram", domain.DisableState{Administrative: true, Telegram: true, UsableTelegram: true}, false},
		{"unusable email blocks even with telegram", domain.DisableState{Email: true, Telegram: true, UsableTelegram: true}, false},
		{"unusable telegram blocks even with email", domain.DisableState{Telegram: true, Email: true, UsableEmail: true}, false},
		{"optional admin without other factors", domain.DisableState{Administrative: true}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := domain.CanDisableTOTP(c.state)
			if c.allowed && err != nil || !c.allowed && !errors.Is(err, domain.ErrRequiredByPolicy) {
				t.Fatal(err)
			}
		})
	}
}
