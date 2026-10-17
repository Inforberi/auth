package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func (r *Repository) RecordActivity(ctx context.Context, user accountdomain.UserID, tokenHash string) (*service.ActivityResult, error) {
	var result service.ActivityResult
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users
			WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, user).Scan(&version); err != nil {
			return sessionError(err)
		}
		// One winner per stored interval, including concurrent tabs/instances. SQL owns time.
		err := tx.QueryRow(ctx, `UPDATE auth.role_bound_sessions
			SET expires_at=LEAST(statement_timestamp()+idle_timeout_seconds*interval '1 second',absolute_expires_at)
			WHERE token_hash=$1 AND user_id=$2 AND auth_version=$3 AND revoked_at IS NULL
			AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
			AND idle_timeout_seconds>0
			AND expires_at<=statement_timestamp()+(idle_timeout_seconds-activity_interval_seconds)*interval '1 second'
			AND expires_at<absolute_expires_at RETURNING expires_at`, tokenHash, user, version).Scan(&result.ExpiresAt)
		if err == nil {
			result.Extended = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// A coalesced activity report and an ordinary session are valid no-ops, not failures.
		err = tx.QueryRow(ctx, `SELECT expires_at FROM auth.role_bound_sessions
			WHERE token_hash=$1 AND user_id=$2 AND auth_version=$3 AND revoked_at IS NULL
			AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()`, tokenHash, user, version).Scan(&result.ExpiresAt)
		return sessionError(err)
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
