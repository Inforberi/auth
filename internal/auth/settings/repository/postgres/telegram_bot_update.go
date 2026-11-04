package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
)

func (r *Repository) AuthorizeTelegramBotUpdate(ctx context.Context, actor accessservice.Principal, version int64) (settingstelegram.TelegramBotStored, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var stored settingstelegram.TelegramBotStored
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := accesspostgres.AuthorizeMutation(ctx, tx, actor, "", settings.AuthSettingsManage)
		if err != nil {
			return err
		}
		stored, err = scanTelegramBot(tx.QueryRow(ctx, `SELECT `+telegramBotColumns+telegramBotEncryptedColumns+telegramBotFrom+` FOR SHARE OF m`), true)
		if err != nil {
			return err
		}
		if stored.Version != version {
			return domain.ErrPolicyConflict
		}
		return checkTelegramSettingsDeadline(ctx, tx, deadline)
	})
	return stored, err
}

func (r *Repository) UpdateTelegramBot(ctx context.Context, input settingstelegram.TelegramBotUpdate) (domain.TelegramBotSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var result domain.TelegramBotSnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage)
		if err != nil {
			return err
		}
		before, err := scanTelegramBot(tx.QueryRow(ctx, `SELECT `+telegramBotColumns+telegramBotFrom+` FOR UPDATE OF m`), false)
		if err != nil {
			return err
		}
		if before.Version != input.ExpectedVersion {
			return domain.ErrPolicyConflict
		}
		if before.BotID != input.Identity.ID {
			var inUse bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_telegram)`).Scan(&inUse); err != nil {
				return err
			}
			if inUse {
				return domain.ErrTelegramFactorInUse
			}
		}
		if err := tx.QueryRow(ctx, `UPDATE auth.mfa_settings SET telegram_bot_id=$1,version=version+1
 WHERE singleton RETURNING version`, input.Identity.ID).Scan(&result.Version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.telegram_bot_settings(singleton,bot_id,username,token,webhook_secret)
 VALUES(true,$1,$2,$3,$4) ON CONFLICT(singleton) DO UPDATE SET bot_id=EXCLUDED.bot_id,
 username=EXCLUDED.username,token=EXCLUDED.token,webhook_secret=EXCLUDED.webhook_secret`,
			input.Identity.ID, input.Identity.Username, input.Token, input.Webhook); err != nil {
			return err
		}
		result.BotID, result.Username, result.TokenSet, result.WebhookSecretSet = input.Identity.ID, input.Identity.Username, true, true
		if _, err := tx.Exec(ctx, `INSERT INTO auth.telegram_bot_settings_audit(actor_id,version,previous_configuration,next_configuration)
 VALUES($1,$2,$3,$4)`, input.Actor.UserID, result.Version, before.TelegramBotSnapshot, result); err != nil {
			return err
		}
		return checkTelegramSettingsDeadline(ctx, tx, deadline)
	})
	return result, err
}

func checkTelegramSettingsDeadline(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
		return err
	}
	if !fresh {
		return accessdomain.ErrFreshAuthRequired
	}
	return nil
}
