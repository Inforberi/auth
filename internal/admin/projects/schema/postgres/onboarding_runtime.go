package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
)

// CheckOnboardingRuntime is a read-only cold-open probe, not authority to activate a database.
func CheckOnboardingRuntime(ctx context.Context, db *pgxpool.Pool, proof credentials.SetupProof) error {
	return checkPreparedRuntime(ctx, db, proof, true)
}

// CheckManagedRuntime attests the closed owner-managed profile, not public Auth readiness.
func CheckManagedRuntime(ctx context.Context, db *pgxpool.Pool, proof credentials.SetupProof) error {
	return checkPreparedRuntime(ctx, db, proof, false)
}

func checkPreparedRuntime(ctx context.Context, db *pgxpool.Pool, proof credentials.SetupProof, firstAdminFlow bool) error {
	args, err := runtimeProfileArguments(proof.Binding())
	if err != nil || db == nil || proof.Digest() == "" {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var safe bool
	err = db.QueryRow(ctx, `SELECT (`+projectRuntimeProfileSQL+`)
		AND EXISTS(SELECT 1 FROM auth.initial_setup WHERE singleton AND operator_hash=$10 AND initialized_at IS NULL
			AND ($11 OR (request_hash IS NULL AND payload IS NULL AND attempts=0)))
		AND EXISTS(SELECT 1 FROM auth.auth_settings WHERE singleton AND version=1 AND password_enabled=$11
			AND NOT(registration_enabled OR email_otp_enabled OR google_enabled OR telegram_enabled
			OR google_registration_enabled OR telegram_registration_enabled OR token_session_exchange_enabled OR token_native_enabled)
			AND password_email_verification='disabled')`, append(args, proof.Digest(), firstAdminFlow)...).Scan(&safe)
	if err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	if !safe {
		return domain.ErrConflict
	}
	return nil
}
