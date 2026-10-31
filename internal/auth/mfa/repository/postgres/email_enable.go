package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) EnableEmailFactor(ctx context.Context, proof service.Proof) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := r.lockEmailFactorManagement(ctx, tx, proof)
		if err != nil {
			return err
		}
		var allowed bool
		if err := tx.QueryRow(ctx, `SELECT email_factor_allowed FROM auth.mfa_settings WHERE singleton FOR SHARE`).Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return domain.ErrUnavailable
		}
		var emailID string
		var mailDeadline time.Time
		err = tx.QueryRow(ctx, `SELECT e.id,s.email_reauthenticated_at+interval '5 minutes'
 FROM auth.role_bound_sessions s JOIN auth.user_emails e ON e.id=s.email_reauthenticated_id AND e.user_id=s.user_id
 WHERE s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3 AND e.verified_at IS NOT NULL
 AND s.email_reauthenticated_at<=clock_timestamp() AND s.email_reauthenticated_at>clock_timestamp()-interval '5 minutes'
 FOR SHARE OF e`, proof.UserID, proof.TokenHash, proof.AuthVersion).Scan(&emailID, &mailDeadline)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrProofRequired
		}
		if err != nil {
			return err
		}
		if mailDeadline.Before(deadline) {
			deadline = mailDeadline
		}
		changed, err := tx.Exec(ctx, `INSERT INTO auth.mfa_email(user_id,email_id) VALUES($1,$2)
 ON CONFLICT(user_id) DO UPDATE SET email_id=EXCLUDED.email_id,enabled_at=clock_timestamp(),suspended_at=NULL
 WHERE auth.mfa_email.suspended_at IS NOT NULL`, proof.UserID, emailID)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return domain.ErrConflict
		}
		if err := invalidateFactors(ctx, tx, proof.UserID); err != nil {
			return err
		}
		if err := audit(ctx, tx, proof.UserID, "email_factor_enabled"); err != nil {
			return err
		}
		return emailFactorDeadline(ctx, tx, deadline)
	})
}
