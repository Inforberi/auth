package service

import (
	"context"
	"errors"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type RetentionUpdateInput struct {
	Actor             accessservice.Principal
	ExpectedVersion   int64
	Policy            domain.RetentionPolicy
	ConfirmShortening bool
}

type RetentionRepository interface {
	LoadRetention(context.Context) (domain.RetentionSnapshot, error)
	InitializeRetention(context.Context, domain.RetentionPolicy) (domain.RetentionSnapshot, error)
	ReadRetention(context.Context, accessservice.Principal) (domain.RetentionSnapshot, error)
	UpdateRetention(context.Context, RetentionUpdateInput) (domain.RetentionSnapshot, error)
}

type Retention struct{ repo RetentionRepository }

func NewRetention(repo RetentionRepository) *Retention { return &Retention{repo: repo} }

func (s *Retention) Initialize(ctx context.Context, seed domain.RetentionPolicy) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.LoadRetention(ctx)
	if errors.Is(err, domain.ErrNotInitialized) {
		if err := seed.Validate(); err != nil {
			return err
		}
		stored, err = s.repo.InitializeRetention(ctx, seed)
	}
	if err != nil {
		return err
	}
	return stored.Policy.Validate()
}

// Current is the worker's per-batch read; an unavailable row never falls back to ENV.
func (s *Retention) Current(ctx context.Context) (domain.RetentionPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.LoadRetention(ctx)
	if err != nil {
		return domain.RetentionPolicy{}, err
	}
	if err := stored.Policy.Validate(); err != nil {
		return domain.RetentionPolicy{}, err
	}
	return stored.Policy, nil
}

func (s *Retention) Read(ctx context.Context, actor accessservice.Principal) (domain.RetentionSnapshot, error) {
	if actor.Validate() != nil {
		return domain.RetentionSnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadRetention(ctx, actor)
}

func (s *Retention) Update(ctx context.Context, input RetentionUpdateInput) (domain.RetentionSnapshot, error) {
	if input.Actor.Validate() != nil {
		return domain.RetentionSnapshot{}, accessdomain.ErrForbidden
	}
	if input.ExpectedVersion < 1 {
		return domain.RetentionSnapshot{}, domain.ErrInvalidRetention
	}
	if err := input.Policy.Validate(); err != nil {
		return domain.RetentionSnapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.UpdateRetention(ctx, input)
}
