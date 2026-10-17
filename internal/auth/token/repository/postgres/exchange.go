package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
)

type Repository struct{ db *pgxpool.Pool }

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

// Exchange owns the authorization snapshot, local signing and audit commit. The callback must not do I/O.
func (r *Repository) Exchange(ctx context.Context, input service.ExchangeInput, mode string, sign func(context.Context, service.SessionProof) (*signing.SignedToken, error)) (*signing.SignedToken, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Keep the original error; commit closes the transaction.
	}()
	if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
		return nil, err
	}
	proof, err := lockSession(ctx, tx, input, "browser")
	if err != nil {
		return nil, err
	}
	result, err := sign(ctx, proof)
	if err != nil {
		return nil, err
	}
	if result == nil || result.Raw == "" || result.ExpiresAt.After(proof.Deadline) {
		return nil, domain.ErrUnavailable
	}
	// Expiry may have elapsed during signing. Never commit an already-expired issuance.
	tag, err := tx.Exec(ctx, `INSERT INTO auth.token_issuance_audit(user_id,session_id,token_id,audience,scope,validation_mode,expires_at)
		SELECT $1,$2,$3,$4,$5,$6,$7 WHERE $7::timestamptz>clock_timestamp()`,
		input.Actor.UserID, input.SessionID, result.ID, input.Audience, input.Scope, mode, result.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, sessiondomain.ErrSessionExpired
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func lockSession(ctx context.Context, tx pgx.Tx, input service.ExchangeInput, profile string) (service.SessionProof, error) {
	var proof service.SessionProof
	err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users
		WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, input.Actor.UserID).Scan(&proof.AuthVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return proof, sessiondomain.ErrSessionNotFound
	}
	if err != nil {
		return proof, err
	}
	return sessionProof(ctx, tx, input, profile, proof.AuthVersion)
}

// The caller holds the user lock and supplies its current auth_version.
func sessionProof(ctx context.Context, tx pgx.Tx, input service.ExchangeInput, profile string, version int64) (service.SessionProof, error) {
	proof := service.SessionProof{AuthVersion: version}
	var verified *time.Time
	var allowed, mfaReady bool
	err := tx.QueryRow(ctx, `SELECT LEAST(s.expires_at,s.absolute_expires_at),COALESCE(s.primary_method,''),s.primary_verified_at,s.mfa_verified_at,
		NOT EXISTS(SELECT 1 FROM unnest($5::text[]) needed(key) WHERE NOT EXISTS(
			SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
			WHERE ur.user_id=s.user_id AND rp.permission_key=needed.key)),
		NOT (EXISTS(SELECT 1 FROM auth.mfa_totp m WHERE m.user_id=s.user_id) OR auth.role_requires_mfa(s.user_id))
			OR (s.mfa_verified_at IS NOT NULL AND EXISTS(SELECT 1 FROM auth.mfa_totp m WHERE m.user_id=s.user_id)),
		clock_timestamp()
		FROM auth.role_bound_sessions s WHERE s.user_id=$1 AND s.token_hash=$2 AND s.id=$3 AND s.auth_version=$4
		AND s.credential_profile=$6
		AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions p WHERE p.user_id=s.user_id AND (p.activated_at IS NULL OR p.password_change_required))
		AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials t WHERE t.user_id=s.user_id)
		FOR SHARE OF s`, input.Actor.UserID, input.Actor.TokenHash, input.SessionID, proof.AuthVersion, input.Scope, profile).
		Scan(&proof.Deadline, &proof.Method, &verified, &proof.MFAVerifiedAt, &allowed, &mfaReady, &proof.Now)
	if errors.Is(err, pgx.ErrNoRows) {
		return proof, sessiondomain.ErrSessionNotFound
	}
	if err != nil {
		return proof, err
	}
	if verified == nil {
		return proof, sessiondomain.ErrSessionNotFound
	}
	if !mfaReady {
		return proof, sessiondomain.ErrMFARequired
	}
	if !allowed {
		return proof, domain.ErrForbidden
	}
	policy, err := settingspostgres.LockPublicPolicy(ctx, tx)
	if err != nil {
		return proof, err
	}
	if err := settingspostgres.RequireSessionVerification(ctx, tx, input.Actor.UserID, proof.Method, policy); err != nil {
		return proof, err
	}
	proof.VerifiedAt = *verified
	return proof, nil
}
