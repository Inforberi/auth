package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func (r *Repository) ReadTelegramMFAPolicy(ctx context.Context, actor accessservice.Principal) (domain.TelegramMFASnapshot, error) {
	var result domain.TelegramMFASnapshot
	err := r.db.QueryRow(ctx, `SELECT version,telegram_factor_allowed FROM auth.mfa_settings WHERE singleton AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage).Scan(&result.Version, &result.Allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TelegramMFASnapshot{}, accessdomain.ErrForbidden
	}
	return result, err
}

func (r *Repository) UpdateTelegramMFAPolicy(ctx context.Context, input service.TelegramMFAUpdate, ready bool) (domain.TelegramMFASnapshot, error) {
	var result domain.TelegramMFASnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage)
		if err != nil {
			return err
		}
		if err := RequireAPISettings(ctx, tx); err != nil {
			return err
		}
		var before domain.TelegramMFASnapshot
		var credentials bool
		if err := tx.QueryRow(ctx, `SELECT version,telegram_factor_allowed,EXISTS(
 SELECT 1 FROM auth.telegram_bot_settings b WHERE b.bot_id=p.telegram_bot_id)
 FROM auth.mfa_settings p WHERE singleton FOR UPDATE`).Scan(&before.Version, &before.Allowed, &credentials); err != nil {
			return err
		}
		if before.Version != input.ExpectedVersion {
			return domain.ErrPolicyConflict
		}
		if input.Allowed && (!ready || !credentials) {
			return domain.ErrMethodNotReady
		}
		if before.Allowed == input.Allowed {
			result = before
			return checkTelegramSettingsDeadline(ctx, tx, deadline)
		}
		if !input.Allowed {
			var configured bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_telegram)`).Scan(&configured); err != nil {
				return err
			}
			if configured {
				return domain.ErrTelegramFactorInUse
			}
		}
		if err := tx.QueryRow(ctx, `UPDATE auth.mfa_settings SET telegram_factor_allowed=$1,version=version+1
 WHERE singleton RETURNING version,telegram_factor_allowed`, input.Allowed).Scan(&result.Version, &result.Allowed); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_settings_audit(actor_id,version,previous_configuration,next_configuration)
 VALUES($1,$2,$3,$4)`, input.Actor.UserID, result.Version, before, result); err != nil {
			return err
		}
		return checkTelegramSettingsDeadline(ctx, tx, deadline)
	})
	return result, err
}
