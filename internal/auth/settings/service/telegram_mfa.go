package service

import (
	"context"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type (
	TelegramMFAUpdate = FactorMFAUpdate
	TelegramMFA       = factorMFA[domain.TelegramMFASnapshot]
)

type TelegramMFARepository interface {
	ReadTelegramMFAPolicy(context.Context, accessservice.Principal) (domain.TelegramMFASnapshot, error)
	UpdateTelegramMFAPolicy(context.Context, TelegramMFAUpdate, bool) (domain.TelegramMFASnapshot, error)
}

// ready comes from a complete runtime, never from an administrator request.
func NewTelegramMFA(repo TelegramMFARepository, ready bool) *TelegramMFA {
	return &TelegramMFA{read: repo.ReadTelegramMFAPolicy, write: repo.UpdateTelegramMFAPolicy, ready: ready}
}
