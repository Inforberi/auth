package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type identityManagementRepository interface {
	RequireIdentityFreshAuth(context.Context, domain.UserID, string, time.Duration) error
	LinkIdentity(context.Context, domain.UserID, string, domain.IdentityKey, time.Duration) error
	UnlinkIdentity(context.Context, domain.UserID, string, string, time.Duration) error
}

type IdentityManagement struct {
	repo     identityManagementRepository
	freshFor time.Duration
}

func NewIdentityManagement(repo identityManagementRepository, freshFor time.Duration) *IdentityManagement {
	return &IdentityManagement{repo: repo, freshFor: freshFor}
}

func (s *IdentityManagement) RequireFresh(ctx context.Context, user domain.UserID, session string) error {
	if err := s.validateSession(user, session); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.RequireIdentityFreshAuth(ctx, user, session, s.freshFor)
}

func (s *IdentityManagement) Link(ctx context.Context, user domain.UserID, session string, key domain.IdentityKey) error {
	if err := s.validateSession(user, session); err != nil {
		return err
	}
	if err := key.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.LinkIdentity(ctx, user, session, key, s.freshFor)
}

func (s *IdentityManagement) Unlink(ctx context.Context, user domain.UserID, session, issuer string) error {
	if err := s.validateSession(user, session); err != nil {
		return err
	}
	if issuer == "" || len(issuer) > 512 {
		return domain.ErrInvalidIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.UnlinkIdentity(ctx, user, session, issuer, s.freshFor)
}

func (s *IdentityManagement) validateSession(user domain.UserID, session string) error {
	if !domain.ValidUserID(user) || len(session) != 64 || s.freshFor <= 0 {
		return domain.ErrFreshAuthRequired
	}
	return nil
}
