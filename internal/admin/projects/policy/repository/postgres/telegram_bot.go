package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspg "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/managementaudit"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	telegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
)

func (r *RuntimeAuthPolicy) ReadProjectBot(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (settings.TelegramBotSnapshot, error) {
	stored, err := r.projectBot(ctx, actor, target, false)
	return stored.TelegramBotSnapshot, err
}

func (r *RuntimeAuthPolicy) projectBot(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, secrets bool) (telegram.TelegramBotStored, error) {
	var result telegram.TelegramBotStored
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operators.Permission{operators.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		if secrets {
			if err := settingspg.CheckAPISettings(ctx, tx); err != nil {
				return sqlerrors.Policy(ctx, err)
			}
		}
		var err error
		result, err = settingspg.ReadTelegramBotInTransaction(ctx, tx, secrets)
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

func (r *RuntimeAuthPolicy) UpdateProjectBot(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, input telegram.TelegramBotUpdateInput) (settings.TelegramBotSnapshot, error) {
	if input.ExpectedVersion < 1 || input.BotToken == nil && !input.RotateWebhookSecret {
		return settings.TelegramBotSnapshot{}, settings.ErrInvalidTelegramBot
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	profile, err := r.projectSettings(ctx, actor, target)
	if err != nil {
		return settings.TelegramBotSnapshot{}, err
	}
	if profile.TelegramMFA == nil {
		return settings.TelegramBotSnapshot{}, domain.ErrUnavailable
	}
	before, err := r.projectBot(ctx, actor, target, true)
	if err != nil {
		return settings.TelegramBotSnapshot{}, err
	}
	if before.Version != input.ExpectedVersion {
		return settings.TelegramBotSnapshot{}, settings.ErrPolicyConflict
	}
	prepared, err := profile.TelegramMFA.PreparePlatformBot(ctx, actor.UserID, input, before)
	if err != nil {
		return settings.TelegramBotSnapshot{}, err
	}
	var result settings.TelegramBotSnapshot
	err = r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var err error
		result, err = settingspg.ApplyTelegramBot(ctx, tx, prepared, func(before, after settings.TelegramBotSnapshot) error {
			return managementaudit.Record(ctx, tx, actor.UserID, "telegram_bot_updated", "telegram-bot", before, after)
		})
		if errors.Is(err, settings.ErrTelegramFactorInUse) {
			return err
		}
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

func (r *RuntimeAuthPolicy) ActivateProjectWebhook(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, version int64) (settings.TelegramBotSnapshot, error) {
	if version < 1 {
		return settings.TelegramBotSnapshot{}, settings.ErrInvalidTelegramBot
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stored, err := r.projectBot(ctx, actor, target, true)
	if err != nil {
		return settings.TelegramBotSnapshot{}, err
	}
	profile, err := r.projectSettings(ctx, actor, target)
	if err != nil {
		return settings.TelegramBotSnapshot{}, err
	}
	if profile.TelegramMFA == nil {
		return settings.TelegramBotSnapshot{}, settings.ErrMethodNotReady
	}
	if err := profile.TelegramMFA.RegisterPlatformWebhook(ctx, actor.UserID, version, stored); err != nil {
		return settings.TelegramBotSnapshot{}, err
	}
	var result settings.TelegramBotSnapshot
	err = r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		before, after, err := settingspg.ApplyTelegramWebhook(ctx, tx, version)
		if err != nil {
			return sqlerrors.Policy(ctx, err)
		}
		result = after
		return managementaudit.Record(ctx, tx, actor.UserID, "telegram_webhook_registered", "telegram-bot", before, after)
	})
	return result, err
}
