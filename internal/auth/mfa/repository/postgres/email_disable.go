package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) DisableEmailFactor(ctx context.Context, proof service.Proof) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := r.lockPasswordFactorManagement(ctx, tx, proof)
		if err != nil {
			return err
		}
		var lastRequired bool
		if err := tx.QueryRow(ctx, `SELECT auth.mfa_required($1) AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, proof.UserID).Scan(&lastRequired); err != nil {
			return err
		}
		if lastRequired {
			return domain.ErrRequiredByPolicy
		}
		changed, err := tx.Exec(ctx, `DELETE FROM auth.mfa_email WHERE user_id=$1`, proof.UserID)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return domain.ErrConflict
		}
		if err := invalidateFactors(ctx, tx, proof.UserID); err != nil {
			return err
		}
		if err := audit(ctx, tx, proof.UserID, "email_factor_disabled"); err != nil {
			return err
		}
		return factorManagementDeadline(ctx, tx, deadline)
	})
}
