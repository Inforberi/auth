package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (r *Repository) CompleteNativeMFA(ctx context.Context, p service.NativeMFAParams, authorize func(mfaservice.NativeTarget) (string, error), sign service.NativeSigner) (*service.RefreshResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Keep the original failure; successful commit closes the transaction.
	}()
	if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
		return nil, err
	}
	factor, err := mfapostgres.CompleteNativeFactor(ctx, tx, p.Attempt)
	if err != nil {
		return nil, err
	}
	if factor.Rejected {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, mfadomain.ErrInvalidCode
	}
	mode, err := authorize(factor.Target)
	if err != nil {
		return nil, err
	}
	params := service.NativeParams{Input: service.NativeInput{Proof: factor.Proof, Audience: factor.Target.Audience, Scope: factor.Target.Scope, UserAgent: p.UserAgent, IP: p.IP}, Policy: p.Policy, Mode: mode, LedgerVerifier: p.LedgerVerifier, RefreshVerifier: p.RefreshVerifier}
	result, err := issueNativeSession(ctx, tx, params, &factor.VerifiedAt, sign)
	if err != nil {
		return nil, err
	}
	if err := mfapostgres.FinishNativeLogin(ctx, tx, p.Attempt); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
