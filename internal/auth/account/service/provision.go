package service

import (
	"context"
	"strconv"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type ProvisionInput struct {
	ActorID        domain.UserID
	IdempotencyKey string
	Email          string
	Invite         bool
}

type ProvisionResult struct {
	UserID domain.UserID
	Reused bool
}

type ProvisionCommand struct {
	Input       ProvisionInput
	Fingerprint string
	Invitation  domain.Invitation
	TTL         time.Duration
}

type provisionRepository interface {
	ProvisionAccount(context.Context, ProvisionCommand) (*ProvisionResult, error)
	InvitationAddress(context.Context, domain.UserID) (string, error)
	ReissueInvitation(context.Context, InvitationReissueCommand) (*ProvisionResult, error)
}

type ProvisionService struct {
	repo    provisionRepository
	account *Service
	cfg     InvitationConfig
}

func NewProvisioning(repo provisionRepository, account *Service, cfg InvitationConfig) *ProvisionService {
	if cfg.ReissueCooldown == 0 {
		cfg.ReissueCooldown = time.Minute
	}
	if cfg.ReissueActorAttemptsPerMinute == 0 {
		cfg.ReissueActorAttemptsPerMinute = 30
	}
	if cfg.ReissueProjectAttemptsPerMinute == 0 {
		cfg.ReissueProjectAttemptsPerMinute = 100
	}
	return &ProvisionService{repo: repo, account: account, cfg: cfg}
}

func (s *ProvisionService) Provision(ctx context.Context, input ProvisionInput) (*ProvisionResult, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrProvisionDisabled
	}
	if !domain.ValidUserID(input.ActorID) || !domain.ValidUserID(domain.UserID(input.IdempotencyKey)) {
		return nil, domain.ErrProvisionConflict
	}
	if input.Email != "" || input.Invite {
		email, err := domain.NewEmail(input.Email)
		if err != nil {
			return nil, err
		}
		input.Email = email.String()
	}
	command := ProvisionCommand{
		Input: input, TTL: s.cfg.TTL,
		Fingerprint: s.account.cipher.Digest("provision:v1:" + strconv.FormatBool(input.Invite) + ":" + input.Email),
	}
	if input.Invite {
		prepared, err := s.prepareInvitation(input.Email)
		if err != nil {
			return nil, err
		}
		command.Invitation = prepared
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.ProvisionAccount(ctx, command)
}
