package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
)

type provisionRepo struct {
	command accountprovisioning.ProvisionCommand
	calls   int
	reissue accountprovisioning.InvitationReissueCommand
}

func (*provisionRepo) InvitationAddress(context.Context, accessservice.Principal, domain.UserID) (string, error) {
	return "user@example.com", nil
}

func (r *provisionRepo) ReissueInvitation(_ context.Context, c accountprovisioning.InvitationReissueCommand) (*accountprovisioning.ProvisionResult, error) {
	r.reissue = c
	r.calls++
	return &accountprovisioning.ProvisionResult{UserID: c.Input.UserID}, nil
}

func (r *provisionRepo) ProvisionAccount(_ context.Context, c accountprovisioning.ProvisionCommand) (*accountprovisioning.ProvisionResult, error) {
	r.command = c
	r.calls++
	return &accountprovisioning.ProvisionResult{UserID: "00000000-0000-4000-8000-000000000002"}, nil
}

func TestProvisioningPreparation(t *testing.T) {
	limits, cipher := provisionFixture(t)
	repo := &provisionRepo{}
	cfg := accountprovisioning.InvitationConfig{Enabled: true, URL: "https://example.com/activate", TTL: time.Hour, ActivationGlobalLimit: 100}
	s := accountprovisioning.NewProvisioning(repo, limits, cipher, cfg)
	input := accountprovisioning.ProvisionInput{Actor: provisionActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003", Email: " USER@example.com ", Invite: true}
	if _, err := s.Provision(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if repo.calls != 1 || repo.command.Input.Email != "user@example.com" || len(repo.command.Fingerprint) != 64 || len(repo.command.Invitation.Digest) != 64 {
		t.Fatal("invalid prepared command")
	}
	plain, err := cipher.Open(repo.command.Invitation.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var message struct{ To, Body string }
	if err := json.Unmarshal(plain, &message); err != nil {
		t.Fatal(err)
	}
	if message.To != "user@example.com" || !strings.Contains(message.Body, "https://example.com/activate#token=") {
		t.Fatal("invalid activation mail")
	}
	first := repo.command
	if _, err := s.Provision(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != repo.command.Fingerprint || first.Invitation.Digest == repo.command.Invitation.Digest {
		t.Fatal("fingerprint unstable or token reused")
	}
	input.Email = ""
	input.Invite = false
	if _, err := s.Provision(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if len(repo.command.Invitation.Payload) != 0 {
		t.Fatal("bare provisioning queued mail")
	}
}

func TestProvisioningInvalidInputBeforeRepository(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		input   accountprovisioning.ProvisionInput
		want    error
	}{
		{"disabled", false, accountprovisioning.ProvisionInput{}, domain.ErrProvisionDisabled},
		{"ids", true, accountprovisioning.ProvisionInput{}, domain.ErrProvisionConflict},
		{"missing email", true, accountprovisioning.ProvisionInput{Actor: provisionActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003", Invite: true}, domain.ErrEmailRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &provisionRepo{}
			s := accountprovisioning.NewProvisioning(repo, nil, nil, accountprovisioning.InvitationConfig{Enabled: tc.enabled})
			if _, err := s.Provision(context.Background(), tc.input); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if repo.calls != 0 {
				t.Fatal("invalid input reached repository")
			}
		})
	}
}

func provisionActor() accessservice.Principal {
	return accessservice.Principal{UserID: "00000000-0000-4000-8000-000000000001", TokenHash: strings.Repeat("a", 64)}
}

func TestProvisioningSharesReissueBudgets(t *testing.T) {
	limits, cipher := provisionFixture(t)
	repo := &provisionRepo{}
	s := accountprovisioning.NewProvisioning(repo, limits, cipher, accountprovisioning.InvitationConfig{Enabled: true, URL: "https://example.com/activate", TTL: time.Hour})
	input := accountprovisioning.ProvisionInput{Actor: provisionActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003"}
	if _, err := s.Provision(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReissueInvitation(context.Background(), accountprovisioning.InvitationReissueInput{Actor: input.Actor, UserID: "00000000-0000-4000-8000-000000000002", IdempotencyKey: input.IdempotencyKey}); err != nil {
		t.Fatal(err)
	}
	if len(limits.keys) != 4 || limits.keys[0] != limits.keys[2] || limits.keys[1] != limits.keys[3] {
		t.Fatal("create/reissue use separate guessing budgets")
	}
	limits.allowed = false
	if _, err := s.Provision(context.Background(), input); !errors.Is(err, domain.ErrVerificationLimited) || repo.calls != 2 {
		t.Fatal("creation quota failed open", err)
	}
	limits.err = errors.New("Redis unavailable")
	if _, err := s.Provision(context.Background(), input); !errors.Is(err, limits.err) || repo.calls != 2 {
		t.Fatal("Redis failure reached mutation", err)
	}
}
