package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
)

// RotateRefreshFamily is a storage operation, not a published refresh use case.
// The owner first acquires Access snapshot; it must authorize/issue/renew in this same transaction.
// A Reused result MUST be committed before returning 401; it is deliberately not an error.
func RotateRefreshFamily(ctx context.Context, tx pgx.Tx, current, replacement string) (domain.RefreshRotation, error) {
	state, err := lockRefreshRotation(ctx, tx, current, replacement)
	if err != nil {
		return domain.RefreshRotation{}, err
	}
	return rotateLockedRefresh(ctx, tx, state, replacement)
}

func lockRefreshRotation(ctx context.Context, tx pgx.Tx, current, replacement string) (refreshState, error) {
	if !domain.ValidRefreshVerifier(current) || !domain.ValidRefreshVerifier(replacement) || current == replacement {
		return refreshState{}, domain.ErrInvalidRefresh
	}
	return lockRefresh(ctx, tx, current)
}

func rotateLockedRefresh(ctx context.Context, tx pgx.Tx, state refreshState, replacement string) (domain.RefreshRotation, error) {
	result := domain.RefreshRotation{Family: state.Family}
	family := &result.Family
	id, now := family.SessionID, state.Now
	if family.RevokedAt != nil || !family.AbsoluteExpiresAt.After(now) {
		return result, domain.ErrInvalidRefresh
	}
	if state.UsedAt != nil {
		if _, err := tx.Exec(ctx, `UPDATE auth.refresh_families SET revoked_at=clock_timestamp() WHERE session_id=$1`, id); err != nil {
			return result, err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1`, id); err != nil {
			return result, err
		}
		result.Reused = true
		family.RevokedAt = &now
		return result, auditRefresh(ctx, tx, state.UserID, *family, "reuse_detected")
	}
	if !state.Active || !state.Live || replacement == state.LedgerHash {
		return result, domain.ErrInvalidRefresh
	}
	if family.Generation >= domain.MaxRefreshGenerations-1 {
		return result, domain.ErrRefreshLimit
	}
	if family.Generation > 0 && now.Sub(family.LastRotatedAt) < domain.RefreshRotationInterval {
		return result, domain.ErrRefreshEarly
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.refresh_tokens SET used_at=clock_timestamp() WHERE session_id=$1 AND used_at IS NULL`, id); err != nil {
		return result, err
	}
	family.Generation++
	family.LastRotatedAt = now
	if _, err := tx.Exec(ctx, `INSERT INTO auth.refresh_tokens(token_hash,session_id,generation,expires_at) VALUES ($1,$2,$3,$4)`,
		replacement, id, family.Generation, family.AbsoluteExpiresAt); err != nil {
		return result, err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.refresh_families SET generation=$2,last_rotated_at=$3 WHERE session_id=$1`, id, family.Generation, now); err != nil {
		return result, err
	}
	return result, auditRefresh(ctx, tx, state.UserID, *family, "rotated")
}
