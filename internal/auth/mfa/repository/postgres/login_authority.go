package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type lockedLoginChallenge struct {
	service.PrimaryProof
	Digest             string
	Profile            string
	FactorMethod       domain.Method
	FactorEmailID      string
	Target             service.NativeTarget
	EnrollmentRequired bool
	ExpiresAt          time.Time
}

func lockLoginChallenge(ctx context.Context, tx pgx.Tx, digest, binding string, accessLocked bool) (*lockedLoginChallenge, error) {
	return lockLoginChallengeProfile(ctx, tx, digest, binding, accessLocked, "browser")
}

func lockLoginChallengeProfile(ctx context.Context, tx pgx.Tx, digest, binding string, accessLocked bool, profile string) (*lockedLoginChallenge, error) {
	var user accountdomain.UserID
	var administrative bool
	// Inspect intent without locking; administrative flows take Access before user/challenge/factor locks.
	err := tx.QueryRow(ctx, `SELECT user_id,administrative FROM auth.mfa_login_challenges
		WHERE digest=$1 AND binding_hash=$2 AND credential_profile=$3`, digest, binding, profile).Scan(&user, &administrative)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	if administrative && !accessLocked {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return nil, err
		}
	} else if !accessLocked {
		if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
			return nil, err
		}
	}
	var version int64
	err = tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1
		AND status='active' AND deleted_at IS NULL FOR UPDATE`, user).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	proof := lockedLoginChallenge{PrimaryProof: service.PrimaryProof{UserID: user, AuthVersion: version, Administrative: administrative}, Digest: digest, Profile: profile}
	err = tx.QueryRow(ctx, `SELECT primary_method,primary_reference,primary_issuer,primary_verified_at,enrollment_required,expires_at,provider_version,COALESCE(native_audience,''),native_scope,factor_method,COALESCE(factor_email_id::text,'')
		FROM auth.mfa_login_challenges WHERE user_id=$1 AND digest=$2 AND binding_hash=$3 AND auth_version=$4
		AND mfa_policy_revision=(SELECT session_revision FROM auth.mfa_settings WHERE singleton)
		AND administrative=$5 AND credential_profile=$6 AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE`, user, digest, binding, version, administrative, profile).
		Scan(&proof.Method, &proof.Reference, &proof.Issuer, &proof.VerifiedAt, &proof.EnrollmentRequired, &proof.ExpiresAt, &proof.ProviderVersion, &proof.Target.Audience, &proof.Target.Scope, &proof.FactorMethod, &proof.FactorEmailID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrInvalidCode
	}
	return &proof, err
}

func requireLoginDeadline(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
		return err
	}
	if !fresh {
		return domain.ErrInvalidCode
	}
	return nil
}
