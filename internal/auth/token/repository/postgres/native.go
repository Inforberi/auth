package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
)

func (r *Repository) IssueNative(ctx context.Context, p service.NativeParams, sign func(context.Context, service.ExchangeInput, service.SessionProof) (*signing.SignedToken, error)) (*service.RefreshResult, error) {
	if p.Input.Proof.Administrative || p.Input.Proof.Method != "password" {
		return nil, mfadomain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Keep the issuance error; commit already closes the transaction.
	}()
	if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
		return nil, err
	}
	proof := p.Input.Proof
	if err := authorizeNativePrimary(ctx, tx, proof); err != nil {
		return nil, err
	}
	version := proof.AuthVersion
	var id string
	policy := p.Policy
	err = tx.QueryRow(ctx, `INSERT INTO auth.sessions(credential_profile,token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
		primary_method,primary_verified_at,user_agent,ip_address,idle_timeout_seconds,activity_interval_seconds,admin_absolute_seconds)
		VALUES('api',$1,$2,$3,statement_timestamp(),statement_timestamp()+$4::bigint*interval '1 second',
		statement_timestamp()+$5::bigint*interval '1 second','password',LEAST($6::timestamptz,statement_timestamp()),$7,$8,$9,$10,$11) RETURNING id`,
		p.LedgerVerifier, proof.UserID, version, int64(policy.IdleTTL/time.Second), int64(policy.AbsoluteTTL/time.Second), proof.VerifiedAt, p.Input.UserAgent, p.Input.IP,
		int64(min(policy.IdleTTL, policy.Sessions.AdminIdleTimeout)/time.Second),
		int64(min(policy.Sessions.AdminActivityInterval, min(policy.IdleTTL, policy.Sessions.AdminIdleTimeout)/10)/time.Second),
		int64(min(policy.AbsoluteTTL, policy.Sessions.AdminAbsoluteTTL)/time.Second)).Scan(&id)
	if err != nil {
		return nil, err
	}
	input := service.ExchangeInput{Actor: accessservice.Principal{UserID: proof.UserID, TokenHash: p.LedgerVerifier}, SessionID: id, Audience: p.Input.Audience, Scope: p.Input.Scope}
	// RequireLoginPrimary already holds and checks the current public policy in this transaction.
	current, err := sessionAuthority(ctx, tx, input, "api", version)
	if err != nil {
		return nil, err
	}
	family, err := CreateRefreshFamily(ctx, tx, service.CreateRefreshFamilyParams{SessionID: id, Audience: input.Audience, Scope: input.Scope, Verifier: p.RefreshVerifier, IdleTTL: policy.IdleTTL})
	if err != nil {
		return nil, err
	}
	issued, err := sign(ctx, input, current)
	if err != nil {
		return nil, err
	}
	if issued == nil || issued.Raw == "" || issued.ExpiresAt.After(current.Deadline) {
		return nil, domain.ErrUnavailable
	}
	if err := auditIssuance(ctx, tx, input, p.Mode, issued); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &service.RefreshResult{ExchangeResult: &service.ExchangeResult{SignedToken: issued, Audience: input.Audience, Scope: input.Scope, Mode: p.Mode}, RefreshExpiresAt: family.AbsoluteExpiresAt}, nil
}

func authorizeNativePrimary(ctx context.Context, tx pgx.Tx, proof mfaservice.PrimaryProof) error {
	var version int64
	var fresh bool
	err := tx.QueryRow(ctx, `SELECT auth_version,$2::timestamptz<=clock_timestamp()+interval '5 seconds'
		AND $2>clock_timestamp()-interval '1 minute' FROM auth.users
		WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, proof.UserID, proof.VerifiedAt).Scan(&version, &fresh)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (version != proof.AuthVersion || !fresh) {
		return mfadomain.ErrProofRequired
	}
	if err != nil {
		return err
	}
	if err := mfapostgres.RequireLoginPrimary(ctx, tx, proof); err != nil {
		return err
	}
	var required bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1) OR auth.role_requires_mfa($1)`, proof.UserID).Scan(&required); err != nil {
		return err
	}
	if required {
		return sessiondomain.ErrMFARequired
	}
	return nil
}
