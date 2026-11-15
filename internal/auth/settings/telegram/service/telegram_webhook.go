package service

import (
	"context"
	"time"

	account "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type TelegramWebhookRepository interface {
	ConfirmTelegramWebhook(context.Context, accessservice.Principal, int64) (domain.TelegramBotSnapshot, error)
}

func (s *TelegramBotSettings) ActivateWebhook(ctx context.Context, actor accessservice.Principal, version int64, register func(context.Context, TelegramBotCredentials) error) (domain.TelegramBotSnapshot, error) {
	if actor.Validate() != nil {
		return domain.TelegramBotSnapshot{}, accessdomain.ErrForbidden
	}
	if version < 1 || register == nil {
		return domain.TelegramBotSnapshot{}, domain.ErrInvalidTelegramBot
	}
	repo, ok := s.repo.(TelegramWebhookRepository)
	if !ok {
		return domain.TelegramBotSnapshot{}, domain.ErrMethodNotReady
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stored, err := s.repo.AuthorizeTelegramBotUpdate(ctx, actor, version)
	if err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	if err := s.RegisterWebhook(ctx, actor.UserID, version, stored, register); err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	return repo.ConfirmTelegramWebhook(ctx, actor, version)
}

// RegisterWebhook performs the external step after the caller authorizes the actor and reads the current configuration.
func (s *TelegramBotSettings) RegisterWebhook(ctx context.Context, actor account.UserID, version int64, stored TelegramBotStored, register func(context.Context, TelegramBotCredentials) error) error {
	if version < 1 || register == nil {
		return domain.ErrInvalidTelegramBot
	}
	if stored.Version != version {
		return domain.ErrPolicyConflict
	}
	if err := s.admitTelegramBotUpdate(ctx, actor); err != nil {
		return err
	}
	credentials, err := s.openCredentials(stored)
	if err != nil {
		return err
	}
	if err := register(ctx, credentials); err != nil {
		return domain.ErrTelegramBotVerification
	}
	return nil
}
