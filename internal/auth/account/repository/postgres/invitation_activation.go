package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) CheckInvitation(ctx context.Context, digest string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var valid bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.account_invitations i JOIN auth.users u ON u.id=i.user_id
		WHERE i.digest=$1 AND i.expires_at>clock_timestamp() AND u.status='pending' AND u.deleted_at IS NULL
		AND u.auth_version=i.auth_version AND NOT EXISTS(SELECT 1 FROM auth.password_credentials p WHERE p.user_id=u.id)
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions p WHERE p.user_id=u.id AND p.password_change_required))`, digest).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return domain.ErrInvalidInvitation
	}
	return nil
}

func (r *Repository) ActivateInvitation(ctx context.Context, digest, hash string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.transaction(ctx, func(tx pgx.Tx) error {
		var user domain.UserID
		if err := tx.QueryRow(ctx, `SELECT user_id FROM auth.account_invitations WHERE digest=$1`, digest).Scan(&user); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrInvalidInvitation
			}
			return err
		}
		var status domain.Status
		var version domain.AuthVersion
		var deleted *time.Time
		if err := tx.QueryRow(ctx, `SELECT status,auth_version,deleted_at FROM auth.users WHERE id=$1 FOR UPDATE`, user).Scan(&status, &version, &deleted); err != nil {
			return err
		}
		if status != domain.StatusPending || deleted != nil {
			return domain.ErrInvalidInvitation
		}
		var emailID domain.AddressID
		err := tx.QueryRow(ctx, `DELETE FROM auth.account_invitations WHERE digest=$1 AND user_id=$2 AND auth_version=$3
			AND expires_at>clock_timestamp()
			AND NOT EXISTS(SELECT 1 FROM auth.account_provisions p WHERE p.user_id=$2 AND p.password_change_required)
			RETURNING email_id`, digest, user, version).Scan(&emailID)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidInvitation
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES($1,$2,$3)`, user, emailID, hash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1 AND id=$2`, user, emailID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.users SET status='active',auth_version=auth_version+1 WHERE id=$1`, user); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.account_provisions SET activated_at=clock_timestamp() WHERE user_id=$1`, user); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.invitation_audit(user_id,action,auth_version) VALUES($1,'activated',$2)`, user, version+1)
		return err
	})
}
