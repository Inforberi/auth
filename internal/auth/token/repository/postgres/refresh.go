package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
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
	input := service.ExchangeInput{Actor: p.Binding.Actor, SessionID: family.SessionID, Audience: access.Audience, Scope: access.Scope}
	if err := auditIssuance(ctx, tx, input, access.Mode, access.SignedToken); err != nil {
		if errors.Is(err, sessiondomain.ErrSessionExpired) {
			return nil, domain.ErrInvalidRefresh
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &service.RefreshResult{ExchangeResult: access, RefreshExpiresAt: family.AbsoluteExpiresAt}, nil
}
