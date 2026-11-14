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

func (r *Repository) ReadEmailMFAPolicy(ctx context.Context, actor accessservice.Principal) (domain.EmailMFASnapshot, error) {
	var result domain.EmailMFASnapshot
	err := r.db.QueryRow(ctx, `SELECT version,email_factor_allowed FROM auth.mfa_settings WHERE singleton AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage).Scan(&result.Version, &result.Allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.EmailMFASnapshot{}, accessdomain.ErrForbidden
	}
	return result, err
}

func (r *Repository) UpdateEmailMFAPolicy(ctx context.Context, input service.EmailMFAUpdate, ready bool) (domain.EmailMFASnapshot, error) {
	var result domain.EmailMFASnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage)
		if err != nil {
			return err
		}
		if err := RequireAPISettings(ctx, tx); err != nil {
			return err
		}
		if input.ExpectedVersion < 1 {
			return domain.ErrInvalidMFAPolicy
		}
		var before domain.EmailMFASnapshot
		if err := tx.QueryRow(ctx, `SELECT version,email_factor_allowed FROM auth.mfa_settings WHERE singleton FOR UPDATE`).Scan(&before.Version, &before.Allowed); err != nil {
			return err
		}
		if before.Version != input.ExpectedVersion {
			return domain.ErrPolicyConflict
		}
		if input.Allowed && !ready {
			return domain.ErrMethodNotReady
		}
		if before.Allowed == input.Allowed {
			result = before
			return nil
		}
		if !input.Allowed {
			var configured bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_email)`).Scan(&configured); err != nil {
				return err
			}
			if configured {
				return domain.ErrEmailFactorInUse
			}
		}
		if err := tx.QueryRow(ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=$1,version=version+1 WHERE singleton RETURNING version,email_factor_allowed`, input.Allowed).Scan(&result.Version, &result.Allowed); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_settings_audit(actor_id,version,previous_configuration,next_configuration) VALUES($1,$2,$3,$4)`, input.Actor.UserID, result.Version, before, result); err != nil {
			return err
		}
		var fresh bool
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
			return err
		}
		if !fresh {
			return accessdomain.ErrForbidden
		}
		return nil
	})
	if err != nil {
		return domain.EmailMFASnapshot{}, err
	}
	return result, nil
}
