package service

import (
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestPublicAdmissionReadsCurrentPolicy(t *testing.T) {
	repo := &settingsRepository{stored: domain.Snapshot{Version: 1, Policy: domain.Policy{Methods: domain.PublicMethods{Password: true}, Registration: domain.PublicRegistration{Enabled: true}}}}
	svc := New(repo)
	if err := svc.CheckPublic(t.Context(), "password", true); err != nil {
		t.Fatal(err)
	}
	repo.stored.Policy.Registration.Enabled = false
	if err := svc.CheckPublic(t.Context(), "password", true); !errors.Is(err, domain.ErrRegistrationDisabled) {
		t.Fatal("stale registration policy", err)
	}
	if err := svc.CheckPublic(t.Context(), "password", false); err != nil {
		t.Fatal(err)
	}
	repo.stored.Policy.Methods.Password = false
	if err := svc.CheckPublic(t.Context(), "password", false); !errors.Is(err, domain.ErrMethodDisabled) {
		t.Fatal("stale method policy", err)
	}
	repo.loadErr = errors.New("SQL unavailable")
	if err := svc.CheckPublic(t.Context(), "password", false); !errors.Is(err, domain.ErrPolicyUnavailable) {
		t.Fatal("dependency fallback", err)
	}
	if repo.loads != 5 {
		t.Fatal("unexpected reads/cache", repo.loads)
	}
}
