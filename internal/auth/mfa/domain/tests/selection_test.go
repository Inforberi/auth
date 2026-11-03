package domain_test

import (
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func TestMethodSelectionPolicy(t *testing.T) {
	cases := []struct {
		name    string
		state   domain.MethodSelection
		primary string
		admin   bool
		want    domain.Method
		err     error
	}{
		{name: "preferred email", state: domain.MethodSelection{Preferred: domain.EmailCode, TOTP: true, Email: true}, primary: "password", want: domain.EmailCode},
		{name: "preferred telegram unavailable", state: domain.MethodSelection{Preferred: domain.TelegramCode, TOTP: true}, primary: "password", err: domain.ErrUnavailable},
		{name: "unknown preference cannot downgrade", state: domain.MethodSelection{Preferred: "unknown", Email: true}, primary: "password", err: domain.ErrUnavailable},
		{name: "SQL administrative access requires TOTP", state: domain.MethodSelection{Preferred: domain.EmailCode, Email: true, Administrative: true}, primary: "password", want: domain.TOTP},
		{name: "trusted administrative proof requires TOTP", state: domain.MethodSelection{Email: true}, primary: "password", admin: true, want: domain.TOTP},
		{name: "email primary cannot use email factor", state: domain.MethodSelection{Email: true}, primary: "emailotp", want: domain.TOTP},
		{name: "external primary requires TOTP", state: domain.MethodSelection{Telegram: true}, primary: "oidc", want: domain.TOTP},
		{name: "TOTP priority", state: domain.MethodSelection{TOTP: true, Email: true, Telegram: true}, primary: "password", want: domain.TOTP},
		{name: "email priority", state: domain.MethodSelection{Email: true, Telegram: true}, primary: "password", want: domain.EmailCode},
		{name: "telegram only", state: domain.MethodSelection{Telegram: true}, primary: "password", want: domain.TelegramCode},
		{name: "configured factor unavailable", state: domain.MethodSelection{ConfiguredWeak: true}, primary: "password", err: domain.ErrUnavailable},
		{name: "enrollment path", primary: "password", want: domain.TOTP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.state.Select(c.primary, c.admin)
			if got != c.want || !errors.Is(err, c.err) {
				t.Fatalf("got %q %v, want %q %v", got, err, c.want, c.err)
			}
		})
	}
}
