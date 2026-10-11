package service

import (
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestProviderMismatchDoesNotResolveAccount(t *testing.T) {
	fixture := &loginFixture{issuer: "https://oauth.telegram.org"}
	svc := New(Config{Issuer: "https://accounts.google.com", Enabled: true, IPLimit: 30, GlobalLimit: 1000}, fixture, fixture, fixture, fixture, tokengenerate.New(), nil)
	started, err := svc.Start(t.Context(), "ip")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Callback(t.Context(), CallbackInput{Code: "code", State: fixture.state, Binding: started.Binding, IP: "ip"})
	if !errors.Is(err, domain.ErrInvalidFlow) || fixture.resolutions != 0 || fixture.sessions != 0 {
		t.Fatal("mixed provider created authority", err)
	}
}
