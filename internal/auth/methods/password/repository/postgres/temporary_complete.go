package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *TemporaryPasswordRepo) CheckTemporarySetup(ctx context.Context, digest string) (*domain.TemporaryCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var c domain.TemporaryCredential
	err := r.db.QueryRow(ctx, `SELECT c.user_id,c.email_id,c.auth_version,c.password_hash,c.secret_digest
		FROM auth.temporary_password_tokens t JOIN auth.temporary_password_credentials c ON c.user_id=t.user_id
		JOIN auth.users u ON u.id=c.user_id JOIN auth.account_provisions p ON p.user_id=u.id
		WHERE t.digest=$1 AND t.expires_at>clock_timestamp() AND c.expires_at>clock_timestamp()
		AND t.auth_version=c.auth_version AND c.auth_version=u.auth_version
		AND u.status='pending' AND u.deleted_at IS NULL AND p.password_change_required AND p.activated_at IS NULL
		AND NOT EXISTS(SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id=u.id)`, digest).
		Scan(&c.UserID, &c.EmailID, &c.AuthVersion, &c.PasswordHash, &c.SecretDigest)
	if err != nil {
		return nil, temporaryError(err)
	}
	return &c, nil
}

func (r *TemporaryPasswordRepo) CompleteTemporary(ctx context.Context, digest, hash string) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var user accountdomain.UserID
		if err := tx.QueryRow(ctx, `SELECT user_id FROM auth.temporary_password_tokens WHERE digest=$1`, digest).Scan(&user); err != nil {
			return temporaryError(err)
		}
		if err := lockTemporaryUser(ctx, tx, user); err != nil {
			return err
		}
		var emailID accountdomain.AddressID
		var version int64
		err := tx.QueryRow(ctx, `SELECT c.email_id,c.auth_version FROM auth.temporary_password_credentials c
			JOIN auth.users u ON u.id=c.user_id JOIN auth.account_provisions p ON p.user_id=u.id
			WHERE c.user_id=$1 AND c.auth_version=u.auth_version AND c.expires_at>clock_timestamp()
			AND u.status='pending' AND u.deleted_at IS NULL AND p.password_change_required AND p.activated_at IS NULL
			AND NOT EXISTS(SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id=u.id)
			FOR UPDATE OF c`, user).Scan(&emailID, &version)
		if err != nil {
			return temporaryError(err)
		}
		err = tx.QueryRow(ctx, `DELETE FROM auth.temporary_password_tokens WHERE digest=$1 AND user_id=$2
			AND auth_version=$3 AND expires_at>clock_timestamp() RETURNING user_id`, digest, user, version).Scan(&user)
		if err != nil {
			return temporaryError(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES($1,$2,$3)`, user, emailID, hash); err != nil {
			return err
		}
		for _, query := range []string{
			`DELETE FROM auth.temporary_password_credentials WHERE user_id=$1`,
			`DELETE FROM auth.account_invitations WHERE user_id=$1`,
			`DELETE FROM auth.password_resets WHERE user_id=$1`,
			`UPDATE auth.sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE user_id=$1 AND revoked_at IS NULL`,
			`UPDATE auth.account_provisions SET password_change_required=false,activated_at=clock_timestamp() WHERE user_id=$1`,
			`UPDATE auth.users SET status='active',auth_version=auth_version+1 WHERE id=$1`,
		} {
			if _, err := tx.Exec(ctx, query, user); err != nil {
				return err
			}
		}
		// Possession of an operator-issued password never verifies the email contact.
		_, err = tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event,auth_version) VALUES($1,'temporary_password_completed',$2)`, user, version+1)
		return err
	})
}
