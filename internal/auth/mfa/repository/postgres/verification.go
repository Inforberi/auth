package postgres

import (
	"context"
	"errors"
	"time"

	pgx "github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) Consume(ctx context.Context, user accountdomain.UserID, expectedVersion int64, check mfaservice.Check, recovery string) (time.Time, error) {
	var verified time.Time
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var version int64
		err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1
			AND status='active' AND deleted_at IS NULL FOR UPDATE`, user).Scan(&version)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && version != expectedVersion) {
			return domain.ErrInvalidCode
		}
		if err != nil {
			return err
		}
		factor, consumeErr := consumeFactor(ctx, tx, user, check, recovery)
		verified = factor.VerifiedAt
		return consumeErr
	})
	if err != nil {
		return time.Time{}, err
	}
	return verified, nil
}

// The caller locks and validates the user first; challenge completion must share this transaction.
func consumeFactor(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, check mfaservice.Check, recovery string) (domain.Verification, error) {
	var verified time.Time
	var encrypted []byte
	var lastStep int64
	err := tx.QueryRow(ctx, `SELECT secret,last_step,clock_timestamp() FROM auth.mfa_totp WHERE user_id=$1 FOR UPDATE`, user).Scan(&encrypted, &lastStep, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Verification{}, domain.ErrInvalidCode
	}
	if err != nil {
		return domain.Verification{}, err
	}
	event := "totp_verified"
	method := domain.TOTP
	if recovery != "" {
		event = "recovery_used"
		method = domain.RecoveryCode
		result, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id=$1 AND digest=$2`, user, recovery)
		if err != nil {
			return domain.Verification{}, err
		}
		if result.RowsAffected() != 1 {
			return domain.Verification{}, domain.ErrInvalidCode
		}
	} else {
		step, err := check(encrypted, lastStep, verified)
		if err != nil {
			return domain.Verification{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.mfa_totp SET last_step=$2 WHERE user_id=$1`, user, step); err != nil {
			return domain.Verification{}, err
		}
	}
	if err := audit(ctx, tx, user, event); err != nil {
		return domain.Verification{}, err
	}
	return domain.Verification{Method: method, VerifiedAt: verified}, nil
}
