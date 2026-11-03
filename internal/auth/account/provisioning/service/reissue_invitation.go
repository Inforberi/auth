package service

import (
	"context"
	"time"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type InvitationReissueInput struct {
	Actor          accessservice.Principal
	UserID         domain.UserID
	IdempotencyKey string
}

type InvitationReissueCommand struct {
	Input      InvitationReissueInput
	Email      string
	Invitation domain.Invitation
	TTL        time.Duration
	Cooldown   time.Duration
}

func (s *ProvisionService) ReissueInvitation(ctx context.Context, input InvitationReissueInput) (*ProvisionResult, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrProvisionDisabled
	}
	if input.Actor.Validate() != nil || !domain.ValidUserID(input.UserID) || !domain.ValidUserID(domain.UserID(input.IdempotencyKey)) || input.Actor.UserID == input.UserID {
		return nil, domain.ErrProvisionConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.limitIssue(ctx, input.Actor.UserID); err != nil {
		return nil, err
	}
	email, err := s.repo.InvitationAddress(ctx, input.Actor, input.UserID)
	if err != nil {
		return nil, err
	}
	invitation, err := s.prepareInvitation(email)
	if err != nil {
		return nil, err
	}
	return s.repo.ReissueInvitation(ctx, InvitationReissueCommand{
		Input: input, Email: email, Invitation: invitation, TTL: s.cfg.TTL, Cooldown: s.cfg.ReissueCooldown,
	})
}
