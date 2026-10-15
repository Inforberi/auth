package service

import (
	"context"
	"errors"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type Repository interface {
	Load(context.Context) (domain.Snapshot, error)
	Initialize(context.Context, domain.Policy) (domain.Snapshot, error)
	Read(context.Context, accessservice.Principal) (domain.Snapshot, error)
	Update(context.Context, UpdateInput) (domain.Snapshot, error)
}

type Service struct{ repo Repository }

func New(repo Repository) *Service { return &Service{repo: repo} }

// Initialize is for trusted application startup, never a public bootstrap endpoint.
func (s *Service) Initialize(ctx context.Context, initial domain.Policy) (domain.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.Load(ctx)
	if err == nil {
		return stored, nil
	}
	if !errors.Is(err, domain.ErrNotInitialized) {
		return domain.Snapshot{}, err
	}
	if err := initial.Validate(); err != nil {
		return domain.Snapshot{}, err
	}
	return s.repo.Initialize(ctx, initial)
}

func (s *Service) Read(ctx context.Context, actor accessservice.Principal) (domain.Snapshot, error) {
	if actor.Validate() != nil {
		return domain.Snapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.Read(ctx, actor)
}
