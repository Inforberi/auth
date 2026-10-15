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
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

type provisionRepo struct {
	command service.ProvisionCommand
	calls   int
	reissue service.InvitationReissueCommand
}

func (*provisionRepo) InvitationAddress(context.Context, accessservice.Principal, domain.UserID) (string, error) {
	return "user@example.com", nil
}

func (r *provisionRepo) ReissueInvitation(_ context.Context, c service.InvitationReissueCommand) (*service.ProvisionResult, error) {
	r.reissue = c
	r.calls++
	return &service.ProvisionResult{UserID: c.Input.UserID}, nil
}

func (r *provisionRepo) ProvisionAccount(_ context.Context, c service.ProvisionCommand) (*service.ProvisionResult, error) {
	r.command = c
	r.calls++
	return &service.ProvisionResult{UserID: "00000000-0000-4000-8000-000000000002"}, nil
}

func TestProvisioningPreparation(t *testing.T) {
	account, _, _, _, cipher := fixture(t)
	repo := &provisionRepo{}
	cfg := service.InvitationConfig{Enabled: true, URL: "https://example.com/activate", TTL: time.Hour, ActivationGlobalLimit: 100}
	s := service.NewProvisioning(repo, account, cfg)
	input := service.ProvisionInput{Actor: provisionActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003", Email: " USER@example.com ", Invite: true}
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
		input   service.ProvisionInput
		want    error
	}{
		{"disabled", false, service.ProvisionInput{}, domain.ErrProvisionDisabled},
		{"ids", true, service.ProvisionInput{}, domain.ErrProvisionConflict},
		{"missing email", true, service.ProvisionInput{Actor: provisionActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003", Invite: true}, domain.ErrEmailRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &provisionRepo{}
			s := service.NewProvisioning(repo, nil, service.InvitationConfig{Enabled: tc.enabled})
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
	account, _, limits, _, _ := fixture(t)
	repo := &provisionRepo{}
	s := service.NewProvisioning(repo, account, service.InvitationConfig{Enabled: true, URL: "https://example.com/activate", TTL: time.Hour})
	input := service.ProvisionInput{Actor: provisionActor(), IdempotencyKey: "00000000-0000-4000-8000-000000000003"}
	if _, err := s.Provision(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReissueInvitation(context.Background(), service.InvitationReissueInput{Actor: input.Actor, UserID: "00000000-0000-4000-8000-000000000002", IdempotencyKey: input.IdempotencyKey}); err != nil {
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
