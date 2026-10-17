package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestOIDCCredentialRevision(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "rotated"}[rotate], func(t *testing.T) {
			f := &loginFixture{}
			revision := int64(7)
			svc := New(Config{Issuer: "https://oauth.telegram.org", Enabled: true, IPLimit: 30, GlobalLimit: 1000}, f, f, f, f, tokengenerate.New(), nil).
				WithProviderSource(func(context.Context) (Provider, int64, error) { return f, revision, nil })
			flow, err := svc.Start(t.Context(), "127.0.0.1")
			if err != nil || f.flow.ProviderVersion != 7 {
				t.Fatal("version not bound at start", err)
			}
			if rotate {
				revision++
			}
			_, err = svc.Callback(t.Context(), CallbackInput{Code: "code", State: f.state, Binding: flow.Binding, IP: "127.0.0.1", UserAgent: "browser"})
			if rotate {
				if !errors.Is(err, domain.ErrInvalidFlow) || f.proofs != 0 || f.resolutions != 0 || f.sessions != 0 {
					t.Fatal("stale flow reached provider or authority", err)
				}
			} else if err != nil || f.primary.ProviderVersion != 7 {
				t.Fatal("version lost before session/MFA", err)
			}
		})
	}
}

func TestOIDCCredentialSourceFailureHasNoFallback(t *testing.T) {
	f := &loginFixture{}
	svc := New(Config{Enabled: true, IPLimit: 30, GlobalLimit: 1000}, f, f, f, f, tokengenerate.New(), nil).
		WithProviderSource(func(context.Context) (Provider, int64, error) { return nil, 0, errors.New("credentials unavailable") })
	if _, err := svc.Start(t.Context(), "127.0.0.1"); err == nil || f.state != "" {
		t.Fatal("source failure fell back to static credentials", err)
	}
}
