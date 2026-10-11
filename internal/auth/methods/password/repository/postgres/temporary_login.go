package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *TemporaryPasswordRepo) FindTemporary(ctx context.Context, email string) (*domain.TemporaryCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var c domain.TemporaryCredential
	err := r.db.QueryRow(ctx, `SELECT c.user_id,c.email_id,c.auth_version,c.password_hash,c.secret_digest
		FROM auth.temporary_password_credentials c JOIN auth.user_emails e ON e.id=c.email_id AND e.user_id=c.user_id
		JOIN auth.users u ON u.id=c.user_id JOIN auth.account_provisions p ON p.user_id=u.id
		WHERE e.email=$1 AND u.status='pending' AND u.deleted_at IS NULL AND p.password_change_required AND p.activated_at IS NULL
		AND c.auth_version=u.auth_version AND c.expires_at>clock_timestamp()
		AND NOT EXISTS(SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id=u.id)`, email).
		Scan(&c.UserID, &c.EmailID, &c.AuthVersion, &c.PasswordHash, &c.SecretDigest)
	if err != nil {
		return nil, temporaryError(err)
	}
	return &c, nil
}

func (r *TemporaryPasswordRepo) BeginTemporary(ctx context.Context, expected domain.TemporaryCredential, digest string, ttl time.Duration) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockTemporaryUser(ctx, tx, expected.UserID); err != nil {
			return err
		}
		// Lock credential before token, matching expiry cleanup's cascading delete.
		var credentialExpiry time.Time
		err := tx.QueryRow(ctx, `SELECT c.expires_at FROM auth.temporary_password_credentials c
			JOIN auth.users u ON u.id=c.user_id JOIN auth.account_provisions p ON p.user_id=u.id
			WHERE c.user_id=$1 AND c.password_hash=$2 AND c.auth_version=$3 AND u.auth_version=c.auth_version
			AND u.status='pending' AND u.deleted_at IS NULL AND p.password_change_required AND p.activated_at IS NULL
			AND c.expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id=u.id)
			FOR UPDATE OF c`, expected.UserID, expected.PasswordHash, expected.AuthVersion).Scan(&credentialExpiry)
		if err != nil {
			return temporaryError(err)
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.temporary_password_tokens(digest,user_id,auth_version,expires_at)
			VALUES($1,$2,$3,LEAST($4,clock_timestamp()+$5::double precision*interval '1 second'))
			ON CONFLICT(user_id) DO UPDATE SET digest=EXCLUDED.digest,auth_version=EXCLUDED.auth_version,expires_at=EXCLUDED.expires_at
			RETURNING expires_at`, digest, expected.UserID, expected.AuthVersion, credentialExpiry, ttl.Seconds()).Scan(&expires)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event,auth_version) VALUES($1,'temporary_password_started',$2)`, expected.UserID, expected.AuthVersion)
		return err
	})
	return expires, err
}
