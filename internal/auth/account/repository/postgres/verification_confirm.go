package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) Confirm(ctx context.Context, digest string) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		var email domain.AddressID
		var user domain.UserID
		err := tx.QueryRow(ctx, `SELECT e.id,e.user_id FROM auth.email_verifications v
			JOIN auth.user_emails e ON e.id=v.email_id JOIN auth.users u ON u.id=e.user_id
			WHERE v.digest=$1 FOR UPDATE OF u`, digest).Scan(&email, &user)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidVerification
		}
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `DELETE FROM auth.email_verifications v USING auth.user_emails e,auth.users u
			WHERE v.digest=$1 AND v.email_id=e.id AND e.user_id=u.id AND e.verified_at IS NULL
			AND u.status='active' AND u.deleted_at IS NULL AND v.expires_at>clock_timestamp()`, digest)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return domain.ErrInvalidVerification
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE id=$1`, email); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.email_verification_audit(user_id,event) VALUES ($1,'email_verified')`, user)
		return err
	})
}

func (r *Repository) RequireVerified(ctx context.Context, user domain.UserID) error {
	var verified bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_credentials p
		JOIN auth.user_emails e ON e.id=p.email_id AND e.user_id=p.user_id
		JOIN auth.users u ON u.id=p.user_id WHERE p.user_id=$1 AND e.verified_at IS NOT NULL
		AND u.status='active' AND u.deleted_at IS NULL)`, user).Scan(&verified)
	if err != nil {
		return err
	}
	if !verified {
		return domain.ErrEmailUnverified
	}
	return nil
}
