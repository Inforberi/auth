package service

import (
	"context"
	"time"

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
	if _, err := s.repo.AuthorizeTelegramBotUpdate(ctx, actor, version); err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	if err := s.admitTelegramBotUpdate(ctx, actor); err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	credentials, err := s.Credentials(ctx)
	if err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	if credentials.Snapshot.Version != version {
		return domain.TelegramBotSnapshot{}, domain.ErrPolicyConflict
	}
	if err := register(ctx, credentials); err != nil {
		return domain.TelegramBotSnapshot{}, domain.ErrTelegramBotVerification
	}
	return repo.ConfirmTelegramWebhook(ctx, actor, version)
}
