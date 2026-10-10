package service

import (
	"context"
	"errors"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func TestCredentialInputBeforeDependencies(t *testing.T) {
	for _, tc := range []struct {
		name, email, password string
		want                  error
	}{
		{"both missing", "", "", accountdomain.ErrEmailRequired},
		{"email missing", "", "Password123", accountdomain.ErrEmailRequired},
		{"password missing", "user@example.com", "", domain.ErrPasswordRequired},
		{"password before malformed email", "bad", "", domain.ErrPasswordRequired},
		{"password before whitespace email", "   ", "", domain.ErrPasswordRequired},
		{"whitespace email", "   ", "Password123", accountdomain.ErrEmailRequired},
		{"malformed email", "bad", "Password123", accountdomain.ErrEmailInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Nil dependencies ensure invalid input cannot reach DB, hashing or sessions.
			s := New(nil, nil, nil)
			if _, err := s.Register(context.Background(), tc.email, tc.password, "", ""); !errors.Is(err, tc.want) {
				t.Fatal("registration error precedence changed", err)
			}
			if _, err := s.Login(context.Background(), LoginInput{Email: tc.email, Password: tc.password}); !errors.Is(err, tc.want) {
				t.Fatal("login error precedence changed", err)
			}
		})
	}
	email, err := parseCredentials(" USER@example.com ", "legacy-password")
	if err != nil || email.String() != "user@example.com" {
		t.Fatal("normalization changed", email, err)
	}
}
