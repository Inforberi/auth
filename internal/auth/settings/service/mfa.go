package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type MFAChange struct {
	ExpectedVersion int64
	Policy          domain.MFAPolicy
}

type MFAUpdateInput struct {
	Actor accessservice.Principal
	MFAChange
}

type MFARepository interface {
	LoadMFAPolicy(context.Context) (domain.MFASnapshot, error)
	ReadMFAPolicy(context.Context, accessservice.Principal) (domain.MFASnapshot, error)
	UpdateMFAPolicy(context.Context, MFAUpdateInput, bool) (domain.MFASnapshot, error)
}

type MFA struct {
	repo  MFARepository
	ready bool
}

// ready is a trusted assembly capability, never a request field.
func NewMFA(repo MFARepository, ready bool) *MFA { return &MFA{repo: repo, ready: ready} }

func (s *MFA) Current(ctx context.Context) (domain.MFASnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.LoadMFAPolicy(ctx)
	if err != nil {
		return domain.MFASnapshot{}, err
	}
	if err := stored.Policy.Validate(); err != nil {
		return domain.MFASnapshot{}, err
	}
	return stored, nil
}

func (s *MFA) Read(ctx context.Context, actor accessservice.Principal) (domain.MFASnapshot, error) {
	if actor.Validate() != nil {
		return domain.MFASnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadMFAPolicy(ctx, actor)
}

func (s *MFA) Update(ctx context.Context, input MFAUpdateInput) (domain.MFASnapshot, error) {
	if input.Actor.Validate() != nil {
		return domain.MFASnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.UpdateMFAPolicy(ctx, input, s.ready)
}
