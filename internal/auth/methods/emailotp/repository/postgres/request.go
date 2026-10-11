package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
)

func (r *Repository) Issue(ctx context.Context, email string, challenge domain.Challenge) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		var user accountdomain.UserID
		var version int64
		var emailID string
		err := tx.QueryRow(ctx, `SELECT u.id,u.auth_version,e.id FROM auth.user_emails e
   JOIN auth.password_credentials p ON p.email_id=e.id AND p.user_id=e.user_id
   JOIN auth.users u ON u.id=e.user_id
   WHERE e.email=$1 AND e.verified_at IS NOT NULL AND u.status='active' AND u.deleted_at IS NULL
   AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials t WHERE t.user_id=u.id)
   AND NOT EXISTS(SELECT 1 FROM auth.account_provisions a WHERE a.user_id=u.id AND a.activated_at IS NULL)
   FOR UPDATE OF u`, email).Scan(&user, &version, &emailID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.email_login_challenges WHERE user_id=$1`, user); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.email_login_challenges(digest,user_id,email_id,auth_version,verifier,expires_at)
   VALUES ($1,$2,$3,$4,$5,$6)`, challenge.Digest, user, emailID, version, challenge.Verifier, challenge.ExpiresAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.email_login_outbox(digest,payload,expires_at) VALUES ($1,$2,$3)`,
			challenge.Digest, challenge.Payload, challenge.ExpiresAt); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.email_login_audit(user_id,event,auth_version) VALUES ($1,'code_issued',$2)`, user, version)
		return err
	})
}
