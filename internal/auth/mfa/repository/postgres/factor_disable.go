package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type factorRemoval struct {
	query, event  string
	emailFallback bool
	notice        service.PrepareSecurityNotice
	method        domain.Method
}

func (r *Repository) DisableEmailFactor(ctx context.Context, proof service.Proof) error {
	return r.disablePasswordFactor(ctx, proof, factorRemoval{
		query: `DELETE FROM auth.mfa_email WHERE user_id=$1`, event: "email_factor_disabled", method: domain.EmailCode,
	})
}

func (r *Repository) DisableTelegramFactor(ctx context.Context, input service.FactorMutation) error {
	return r.disablePasswordFactor(ctx, input.Proof, factorRemoval{
		query: `DELETE FROM auth.mfa_telegram WHERE user_id=$1`, event: "telegram_factor_disabled", emailFallback: true,
		notice: input.PrepareNotice, method: domain.TelegramCode,
	})
}

func (r *Repository) disablePasswordFactor(ctx context.Context, proof service.Proof, removal factorRemoval) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := r.lockPasswordFactorManagement(ctx, tx, proof)
		if err != nil {
			return err
		}
		var lastRequired bool
		if err := tx.QueryRow(ctx, `SELECT auth.mfa_required($1)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
 AND (NOT $2::boolean OR NOT auth.email_factor_usable($1))`, proof.UserID, removal.emailFallback).Scan(&lastRequired); err != nil {
			return err
		}
		if lastRequired {
			return domain.ErrRequiredByPolicy
		}
		changed, err := tx.Exec(ctx, removal.query, proof.UserID)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return domain.ErrConflict
		}
		if err := clearFactorPreference(ctx, tx, proof.UserID, removal.method); err != nil {
			return err
		}
		if err := invalidateFactors(ctx, tx, proof.UserID); err != nil {
			return err
		}
		if removal.event == "telegram_factor_disabled" {
			if err := telegramFactorNotice(ctx, tx, service.FactorMutation{Proof: proof, PrepareNotice: removal.notice}, removal.event); err != nil {
				return err
			}
		} else if err := audit(ctx, tx, proof.UserID, removal.event); err != nil {
			return err
		}
		return factorManagementDeadline(ctx, tx, deadline)
	})
}
