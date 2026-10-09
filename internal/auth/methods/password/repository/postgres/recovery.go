package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *PasswordRepo) recoveryTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the operation error; commit closes the transaction.
	}()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PasswordRepo) IssueReset(ctx context.Context, email string, prepared domain.ResetChallenge) error {
	return r.recoveryTransaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var user accountdomain.UserID
		var version int64
		err := tx.QueryRow(ctx, `SELECT u.id,u.auth_version FROM auth.users u
			JOIN auth.password_credentials p ON p.user_id=u.id JOIN auth.user_emails e ON e.id=p.email_id AND e.user_id=u.id
			WHERE e.email=$1 AND u.status='active' AND u.deleted_at IS NULL FOR UPDATE OF u`, email).Scan(&user, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var cooldown bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_resets WHERE user_id=$1 AND created_at>clock_timestamp()-interval '1 minute')`, user).Scan(&cooldown); err != nil {
			return err
		}
		if cooldown {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.password_resets WHERE user_id=$1`, user); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.password_resets(digest,user_id,auth_version,expires_at) VALUES ($1,$2,$3,$4)`, prepared.Digest, user, version, prepared.ExpiresAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.password_reset_outbox(digest,payload,expires_at) VALUES ($1,$2,$3)`, prepared.Digest, prepared.Payload, prepared.ExpiresAt); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event) VALUES ($1,'password_reset_issued')`, user)
		return err
	})
}

func (r *PasswordRepo) ConsumeReset(ctx context.Context, digest, passwordHash string) error {
	return r.recoveryTransaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var user accountdomain.UserID
		var version int64
		err := tx.QueryRow(ctx, `SELECT u.id,u.auth_version FROM auth.users u JOIN auth.password_resets r ON r.user_id=u.id WHERE r.digest=$1 FOR UPDATE OF u`, digest).Scan(&user, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidReset
		}
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `DELETE FROM auth.password_resets r USING auth.users u WHERE r.digest=$1 AND r.user_id=u.id
			AND r.auth_version=$2 AND u.auth_version=$2 AND u.status='active' AND u.deleted_at IS NULL AND r.expires_at>clock_timestamp()`, digest, version)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return domain.ErrInvalidReset
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.password_credentials SET password_hash=$2 WHERE user_id=$1`, user, passwordHash); err != nil {
			return err
		}
		return revokeForPassword(ctx, tx, user, "password_reset")
	})
}

func revokeForPassword(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, event string) error {
	if _, err := tx.Exec(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, user); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, user); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.password_resets WHERE user_id=$1`, user); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event) VALUES ($1,$2)`, user, event)
	return err
}
