package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

// ResolveRefresh is an indexed, non-authorizing hint used before distributed budgets.
func (r *Repository) ResolveRefresh(ctx context.Context, verifier string) (service.RefreshBinding, error) {
	var binding service.RefreshBinding
	err := r.db.QueryRow(ctx, `SELECT s.user_id,s.id,s.token_hash FROM auth.refresh_tokens t
		JOIN auth.sessions s ON s.id=t.session_id WHERE t.token_hash=$1`, verifier).
		Scan(&binding.Actor.UserID, &binding.SessionID, &binding.Actor.TokenHash)
	return binding, refreshLookupError(err)
}

// Refresh owns commit, including the denial that must preserve replay revocation.
// The signing callback is local-only; no network I/O is allowed under these locks.
func (r *Repository) Refresh(ctx context.Context, p service.RefreshParams, sign func(context.Context, service.RefreshProof) (*service.ExchangeResult, error)) (*service.RefreshResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the original failure; commit closes the transaction.
	}()
	if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
		return nil, err
	}
	state, err := lockRefreshRotation(ctx, tx, p.Verifier, p.Replacement)
	if err != nil {
		return nil, err
	}
	if state.UserID != p.Binding.Actor.UserID || state.Family.SessionID != p.Binding.SessionID || state.LedgerHash != p.Binding.Actor.TokenHash {
		return nil, domain.ErrInvalidRefresh
	}
	rotation, err := rotateLockedRefresh(ctx, tx, state, p.Replacement)
	if err != nil {
		return nil, err
	}
	family := rotation.Family
	if rotation.Reused {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, domain.ErrInvalidRefresh
	}
	proof, err := refreshProof(ctx, tx, p.Binding, family, state.AuthVersion)
	if err != nil {
		return nil, err
	}
	access, err := sign(ctx, proof)
	if err != nil {
		return nil, err
	}
	if access == nil || access.SignedToken == nil || access.Raw == "" || access.ExpiresAt.After(proof.Deadline) {
		return nil, domain.ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `INSERT INTO auth.token_issuance_audit(user_id,session_id,token_id,audience,scope,validation_mode,expires_at)
		SELECT $1,$2,$3,$4,$5,$6,$7 WHERE $7::timestamptz>clock_timestamp()
		AND EXISTS(SELECT 1 FROM auth.role_bound_sessions WHERE id=$2 AND revoked_at IS NULL
		AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp())`,
		p.Binding.Actor.UserID, family.SessionID, access.ID, access.Audience, access.Scope, access.Mode, access.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, domain.ErrInvalidRefresh
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &service.RefreshResult{ExchangeResult: access, RefreshExpiresAt: family.AbsoluteExpiresAt}, nil
}
