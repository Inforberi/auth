package service

import (
	"context"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
)

func (s *Service) StartLink(ctx context.Context, user accountdomain.UserID, sessionHash, ip string) (*StartedFlow, error) {
	ctx, cancel := flowContext(ctx)
	defer cancel()
	if err := s.admit(ctx, ip); err != nil {
		return nil, err
	}
	if err := s.management.RequireFresh(ctx, user, sessionHash); err != nil {
		return nil, err
	}
	return s.startFlow(ctx, domain.Flow{Purpose: domain.Link, UserID: user, SessionHash: sessionHash})
}

func (s *Service) Unlink(ctx context.Context, user accountdomain.UserID, sessionHash, ip string) error {
	ctx, cancel := flowContext(ctx)
	defer cancel()
	if err := s.admit(ctx, ip); err != nil {
		return err
	}
	return s.management.Unlink(ctx, user, sessionHash, domain.Issuer)
}
