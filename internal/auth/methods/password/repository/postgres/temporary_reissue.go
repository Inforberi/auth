package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func (r *TemporaryPasswordRepo) ReissueTemporary(ctx context.Context, input service.TemporaryReissueInput, credential domain.TemporaryCredential, ttl, cooldown time.Duration) (*service.TemporaryIssueResult, error) {
	result := &service.TemporaryIssueResult{UserID: input.UserID}
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var actor accountdomain.UserID
		err := tx.QueryRow(ctx, `SELECT id FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, input.ActorID).Scan(&actor)
		if errors.Is(err, pgx.ErrNoRows) {
			return accountdomain.ErrProvisionConflict
		}
		if err != nil {
			return err
		}
		if err := lockTemporaryUser(ctx, tx, input.UserID); err != nil {
			return err
		}
		var previous accountdomain.UserID
		err = tx.QueryRow(ctx, `SELECT user_id,expires_at FROM auth.temporary_password_reissues WHERE actor_id=$1 AND request_key=$2`, actor, input.IdempotencyKey).Scan(&previous, &result.ExpiresAt)
		if err == nil {
			if previous != input.UserID {
				return accountdomain.ErrProvisionConflict
			}
			result.Reused = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var ready bool
		var emailID accountdomain.AddressID
		err = tx.QueryRow(ctx, `SELECT p.invitation_email_id,
			p.temporary_password_issued_at+$2::double precision*interval '1 second'<=clock_timestamp()
			FROM auth.account_provisions p JOIN auth.users u ON u.id=p.user_id JOIN auth.user_emails e ON e.id=p.invitation_email_id AND e.user_id=u.id
			WHERE p.user_id=$1 AND p.password_change_required AND p.activated_at IS NULL AND u.status='pending' AND u.deleted_at IS NULL
			AND e.verified_at IS NULL AND NOT EXISTS(SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id=u.id)
			FOR UPDATE OF e`, input.UserID, cooldown.Seconds()).Scan(&emailID, &ready)
		if err != nil {
			return temporaryError(err)
		}
		if !ready {
			return domain.ErrTemporaryPasswordCooldown
		}
		var stored accountdomain.UserID
		err = tx.QueryRow(ctx, `INSERT INTO auth.temporary_password_reissues(actor_id,request_key,user_id,expires_at)
			VALUES($1,$2,$3,clock_timestamp()+$4::double precision*interval '1 second') ON CONFLICT(actor_id,request_key) DO NOTHING RETURNING user_id,expires_at`, actor, input.IdempotencyKey, input.UserID, ttl.Seconds()).Scan(&stored, &result.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return accountdomain.ErrProvisionConflict
		}
		if err != nil {
			return err
		}
		var version int64
		if err := tx.QueryRow(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1 RETURNING auth_version`, input.UserID).Scan(&version); err != nil {
			return err
		}
		for _, query := range []string{
			`DELETE FROM auth.temporary_password_credentials WHERE user_id=$1`,
			`DELETE FROM auth.account_invitations WHERE user_id=$1`,
			`UPDATE auth.sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE user_id=$1 AND revoked_at IS NULL`,
		} {
			if _, err := tx.Exec(ctx, query, input.UserID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.temporary_password_credentials(user_id,email_id,password_hash,secret_digest,auth_version,expires_at)
			VALUES($1,$2,$3,$4,$5,$6)`, input.UserID, emailID, credential.PasswordHash, credential.SecretDigest, version, result.ExpiresAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.account_provisions SET temporary_password_issued_at=clock_timestamp() WHERE user_id=$1`, input.UserID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,actor_id,event,auth_version) VALUES($1,$2,'temporary_password_reissued',$3)`, input.UserID, actor, version)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
