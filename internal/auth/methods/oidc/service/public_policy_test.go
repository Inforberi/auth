package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestPolicyDeniesBeforeProviderWork(t *testing.T) {
	fixture := &loginFixture{}
	service := New(Config{Enabled: true, Issuer: "https://accounts.google.com", CheckPolicy: func(context.Context) error { return settingsdomain.ErrMethodDisabled }}, fixture, nil, nil, nil, nil, nil)
	if _, err := service.Start(t.Context(), ""); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
		t.Fatal(err)
	}
	if _, err := service.Callback(t.Context(), CallbackInput{Code: "code", State: strings.Repeat("A", 43), Binding: strings.Repeat("A", 43)}); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
		t.Fatal(err)
	}
	if _, err := service.StartLink(t.Context(), "user", "session", ""); !errors.Is(err, settingsdomain.ErrMethodDisabled) {
		t.Fatal(err)
	}
}
