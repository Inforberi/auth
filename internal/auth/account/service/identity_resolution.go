package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type identityRepository interface {
	ResolveIdentityAccount(context.Context, domain.IdentityKey, bool) (*domain.User, error)
}

type IdentityResolution struct{ repo identityRepository }

func NewIdentityResolution(repo identityRepository) *IdentityResolution {
	return &IdentityResolution{repo: repo}
}

func (s *IdentityResolution) Resolve(ctx context.Context, key domain.IdentityKey, allowRegistration bool) (*domain.User, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	user, err := s.repo.ResolveIdentityAccount(ctx, key, allowRegistration)
	if err != nil {
		return nil, err
	}
	if user.Status != domain.StatusActive || user.DeletedAt != nil {
		return nil, domain.ErrIdentityUnavailable
	}
	return user, nil
}
