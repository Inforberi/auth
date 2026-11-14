package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (r *Repository) ConfirmTelegramWebhook(ctx context.Context, actor accessservice.Principal, version int64) (domain.TelegramBotSnapshot, error) {
	var result domain.TelegramBotSnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := accesspostgres.AuthorizeMutation(ctx, tx, actor, "", settings.AuthSettingsManage)
		if err != nil {
			return err
		}
		if err := RequireAPISettings(ctx, tx); err != nil {
			return err
		}
		before, err := scanTelegramBot(tx.QueryRow(ctx, `SELECT `+telegramBotColumns+telegramBotFrom+` FOR UPDATE OF m`), false)
		if err != nil {
			return err
		}
		if before.Version != version {
			return domain.ErrPolicyConflict
		}
		if !before.TokenSet || !before.WebhookSecretSet {
			return domain.ErrMethodNotReady
		}
		result = before.TelegramBotSnapshot
		if err := tx.QueryRow(ctx, `UPDATE auth.mfa_settings SET version=version+1 WHERE singleton RETURNING version`).Scan(&result.Version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_settings_audit(actor_id,version,previous_configuration,next_configuration) VALUES($1,$2,$3,$4)`, actor.UserID, result.Version, before.TelegramBotSnapshot, result); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_audit(user_id,event) VALUES($1,'telegram_webhook_registered')`, actor.UserID); err != nil {
			return err
		}
		return checkTelegramSettingsDeadline(ctx, tx, deadline)
	})
	return result, err
}
