package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestPublicPolicyBeforePasswordWork(t *testing.T) {
	service := New(nil, nil, nil, denyLogin{}).WithPublicPolicy(func(context.Context, bool) error { return domain.ErrMethodDisabled })
	input := LoginInput{Email: "user@example.com", Password: "ExamplePass1"}
	if _, err := service.Login(t.Context(), input); !errors.Is(err, domain.ErrMethodDisabled) {
		t.Fatal(err)
	}
	if _, err := service.Register(t.Context(), input.Email, input.Password, "", ""); !errors.Is(err, domain.ErrMethodDisabled) {
		t.Fatal(err)
	}
}
