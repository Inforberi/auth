package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
)

func TestInvitationReissuePreparation(t *testing.T) {
	limits, cipher := provisionFixture(t)
	repo := &provisionRepo{}
	s := accountprovisioning.NewProvisioning(repo, limits, cipher, accountprovisioning.InvitationConfig{Enabled: true, URL: "https://example.com/activate", TTL: time.Hour})
	input := accountprovisioning.InvitationReissueInput{Actor: provisionActor(), UserID: "00000000-0000-4000-8000-000000000002", IdempotencyKey: "00000000-0000-4000-8000-000000000003"}
	result, err := s.ReissueInvitation(context.Background(), input)
	if err != nil || result.UserID != input.UserID || repo.calls != 1 || len(limits.keys) != 2 {
		t.Fatalf("reissue: %v %v", result, err)
	}
	if repo.reissue.Email != "user@example.com" || repo.reissue.Cooldown != time.Minute || len(repo.reissue.Invitation.Digest) != 64 || len(repo.reissue.Invitation.Payload) == 0 {
		t.Fatal("invalid prepared invitation")
	}
	first := repo.reissue.Invitation.Digest
	if _, err := s.ReissueInvitation(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if first == repo.reissue.Invitation.Digest {
		t.Fatal("token reused during preparation")
	}
	limits.allowed = false
	if _, err := s.ReissueInvitation(context.Background(), input); !errors.Is(err, domain.ErrVerificationLimited) || repo.calls != 2 {
		t.Fatal("quota failed open", err)
	}
	limits.err = errors.New("redis unavailable")
	if _, err := s.ReissueInvitation(context.Background(), input); !errors.Is(err, limits.err) || repo.calls != 2 {
		t.Fatal("limiter failure reached repository", err)
	}
}

func TestInvitationReissueRejectsInvalidInput(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		repo := &provisionRepo{}
		s := accountprovisioning.NewProvisioning(repo, nil, nil, accountprovisioning.InvitationConfig{Enabled: enabled})
		want := domain.ErrProvisionDisabled
		if enabled {
			want = domain.ErrProvisionConflict
		}
		if _, err := s.ReissueInvitation(context.Background(), accountprovisioning.InvitationReissueInput{}); !errors.Is(err, want) || repo.calls != 0 {
			t.Fatal("invalid input reached dependencies", err)
		}
	}
}
