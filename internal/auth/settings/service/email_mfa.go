package service

import (
	"context"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type (
	EmailMFAUpdate = FactorMFAUpdate
	EmailMFA       = factorMFA[domain.EmailMFASnapshot]
)

type EmailMFARepository interface {
	ReadEmailMFAPolicy(context.Context, accessservice.Principal) (domain.EmailMFASnapshot, error)
	UpdateEmailMFAPolicy(context.Context, EmailMFAUpdate, bool) (domain.EmailMFASnapshot, error)
}

// ready comes from a complete runtime, never from an administrator request.
func NewEmailMFA(repo EmailMFARepository, ready bool) *EmailMFA {
	return &EmailMFA{read: repo.ReadEmailMFAPolicy, write: repo.UpdateEmailMFAPolicy, ready: ready}
}
