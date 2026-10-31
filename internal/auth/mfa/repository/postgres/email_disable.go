package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) DisableEmailFactor(ctx context.Context, proof service.Proof) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := r.lockEmailFactorManagement(ctx, tx, proof)
		if err != nil {
			return err
		}
		// The management guard requires fresh strong MFA for any configured factor.
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
		return emailFactorDeadline(ctx, tx, deadline)
	})
}
