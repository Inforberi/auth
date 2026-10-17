package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func refreshProof(ctx context.Context, tx pgx.Tx, binding service.RefreshBinding, family domain.RefreshFamily, version int64) (service.RefreshProof, error) {
	var proof service.RefreshProof
	proof.Family = family
	input := service.ExchangeInput{Actor: binding.Actor, SessionID: binding.SessionID}
	// Reuse the same current verification/MFA/provisioning guards as session exchange.
	current, policy, err := sessionProof(ctx, tx, input, "api", version)
	if err != nil {
		return proof, err
	}
	if !policy.TokenIssuance.Native {
		return proof, domain.ErrForbidden
	}
	proof.SessionProof = current
	err = tx.QueryRow(ctx, `SELECT ARRAY(SELECT needed.key FROM unnest($2::text[]) needed(key)
		WHERE EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
		WHERE ur.user_id=$1 AND rp.permission_key=needed.key) ORDER BY needed.key COLLATE "C")`, binding.Actor.UserID, family.Scope).Scan(&proof.GrantedScope)
	if err != nil {
		return proof, err
	}
	// Administrative idle sessions require explicit activity, never background refresh.
	err = tx.QueryRow(ctx, `UPDATE auth.sessions SET expires_at=GREATEST(expires_at,
		LEAST(statement_timestamp()+$2::bigint*interval '1 second',absolute_expires_at))
		WHERE id=$1 AND idle_timeout_seconds=0 AND revoked_at IS NULL
		AND expires_at<LEAST(statement_timestamp()+$2::bigint*interval '1 second',absolute_expires_at)
		AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp() RETURNING expires_at,clock_timestamp()`, family.SessionID, family.IdleSeconds).
		Scan(&proof.Deadline, &proof.Now)
	if errors.Is(err, pgx.ErrNoRows) {
		// A live administrative session is usable but its deadline is not extended.
		return proof, nil
	}
	return proof, err
}
