package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type EmailMFAUpdate struct {
	Actor           accessservice.Principal
	ExpectedVersion int64
	Allowed         bool
}

type EmailMFARepository interface {
	ReadEmailMFAPolicy(context.Context, accessservice.Principal) (domain.EmailMFASnapshot, error)
	UpdateEmailMFAPolicy(context.Context, EmailMFAUpdate, bool) (domain.EmailMFASnapshot, error)
}

type EmailMFA struct {
	repo  EmailMFARepository
	ready bool
}

// ready comes from a complete email-factor runtime, never from a client request.
func NewEmailMFA(repo EmailMFARepository, ready bool) *EmailMFA {
	return &EmailMFA{repo: repo, ready: ready}
}

func (s *EmailMFA) Read(ctx context.Context, actor accessservice.Principal) (domain.EmailMFASnapshot, error) {
	if actor.Validate() != nil {
		return domain.EmailMFASnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadEmailMFAPolicy(ctx, actor)
}

func (s *EmailMFA) Update(ctx context.Context, input EmailMFAUpdate) (domain.EmailMFASnapshot, error) {
	if input.Actor.Validate() != nil {
		return domain.EmailMFASnapshot{}, accessdomain.ErrForbidden
	}
	if input.ExpectedVersion < 1 {
		return domain.EmailMFASnapshot{}, domain.ErrInvalidMFAPolicy
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.UpdateEmailMFAPolicy(ctx, input, s.ready)
}
