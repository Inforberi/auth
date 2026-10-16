package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestPolicyDeniesBeforeOTPStorage(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "email-login:v1")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &loginFixture{allowed: true}
	service := New(nil, cipher, fixture, nil, nil, Config{Enabled: true, ResendInterval: time.Minute, CheckPolicy: func(context.Context) error { return settingsdomain.ErrMethodDisabled }})
	if _, err := service.Request(t.Context(), "user@example.com", ""); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
		t.Fatal(err)
	}
	if _, err := service.Confirm(t.Context(), ConfirmInput{Code: "12345678", Binding: strings.Repeat("A", 43)}); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
		t.Fatal(err)
	}
}
