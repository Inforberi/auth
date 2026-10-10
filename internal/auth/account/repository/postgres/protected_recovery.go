package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ProtectedRecoveryHash(ctx context.Context, digest string) (string, error) {
	var hash string
	err := r.db.QueryRow(ctx, `SELECT p.password_hash FROM auth.email_changes c
		JOIN auth.users u ON u.id=c.user_id
		JOIN auth.password_credentials p ON p.user_id=u.id
		JOIN auth.user_emails e ON e.id=c.email_id AND e.user_id=u.id AND e.email=c.old_email
		WHERE c.recovery_digest=$1 AND c.state='reported' AND c.recovery_expires_at>clock_timestamp()
		AND u.status='blocked' AND u.deleted_at IS NULL AND u.auth_version=c.recovery_version
		AND e.verified_at IS NOT NULL`, digest).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrInvalidAccountRecovery
	}
	return hash, err
}

func cancelProtectedRecovery(ctx context.Context, tx pgx.Tx, user domain.UserID) error {
	// Even an administrative block of an already security-blocked account supersedes recovery.
	if _, err := tx.Exec(ctx, `WITH cancelled AS (
		UPDATE auth.email_changes SET state='cancelled',recovery_version=NULL,recovery_expires_at=NULL
		WHERE user_id=$1 AND recovery_version IS NOT NULL RETURNING user_id,id
	) INSERT INTO auth.email_change_audit(user_id,change_id,event) SELECT user_id,id,'cancelled' FROM cancelled`, user); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM auth.email_change_outbox o USING auth.email_changes c
		WHERE o.change_id=c.id AND c.user_id=$1 AND o.kind='recovery'`, user)
	return err
}

func (r *Repository) RecoverProtectedAccount(ctx context.Context, digest, expectedHash, newHash string) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		var user domain.UserID
		if err := tx.QueryRow(ctx, `SELECT user_id FROM auth.email_changes WHERE recovery_digest=$1`, digest).Scan(&user); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrInvalidAccountRecovery
			}
			return err
		}
		var version domain.AuthVersion
		err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='blocked'
			AND deleted_at IS NULL FOR UPDATE`, user).Scan(&version)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidAccountRecovery
		}
		if err != nil {
			return err
		}
		var id string
		var emailID domain.AddressID
		err = tx.QueryRow(ctx, `SELECT c.id,c.email_id FROM auth.email_changes c
			JOIN auth.user_emails e ON e.id=c.email_id AND e.user_id=c.user_id AND e.email=c.old_email
			JOIN auth.password_credentials p ON p.user_id=c.user_id AND p.password_hash=$3
			WHERE c.recovery_digest=$1 AND c.user_id=$2 AND c.state='reported'
			AND c.recovery_version=$4 AND c.recovery_expires_at>clock_timestamp() AND e.verified_at IS NOT NULL
			FOR UPDATE OF c`, digest, user, expectedHash, version).Scan(&id, &emailID)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidAccountRecovery
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.password_credentials SET email_id=$2,password_hash=$3 WHERE user_id=$1`, user, emailID, newHash); err != nil {
			return err
		}
		// Only the recovered mailbox remains trusted; retain other addresses without proof of ownership.
		if _, err := tx.Exec(ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1 AND id<>$2`, user, emailID); err != nil {
			return err
		}
		if err := invalidateChangeAccess(ctx, tx, user); err != nil {
			return err
		}
		for _, query := range []string{
			`UPDATE auth.users SET status='active' WHERE id=$1`,
			`UPDATE auth.email_changes SET state='cancelled',recovery_version=NULL,recovery_expires_at=NULL WHERE user_id=$1`,
			`DELETE FROM auth.email_change_outbox o USING auth.email_changes c WHERE o.change_id=c.id AND c.user_id=$1`,
		} {
			if _, err := tx.Exec(ctx, query, user); err != nil {
				return err
			}
		}
		return auditEmailChange(ctx, tx, user, id, "recovered")
	})
}
