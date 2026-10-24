package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// CheckOnboardingRuntime is a read-only cold-open probe, not authority to activate a database.
func CheckOnboardingRuntime(ctx context.Context, db *pgxpool.Pool, proof credentials.SetupProof) error {
	args, err := runtimeProfileArguments(proof.Binding())
	if err != nil || db == nil || proof.Digest() == "" {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var safe bool
	err = db.QueryRow(ctx, `SELECT (`+projectRuntimeProfileSQL+`)
		AND EXISTS(SELECT 1 FROM auth.initial_setup WHERE singleton AND operator_hash=$10 AND initialized_at IS NULL)
		AND EXISTS(SELECT 1 FROM auth.auth_settings WHERE singleton AND version=1 AND password_enabled
			AND NOT(registration_enabled OR email_otp_enabled OR google_enabled OR telegram_enabled
			OR google_registration_enabled OR telegram_registration_enabled OR token_session_exchange_enabled OR token_native_enabled)
			AND password_email_verification='disabled')`, append(args, proof.Digest())...).Scan(&safe)
	if err != nil {
		return catalogError(ctx, err)
	}
	if !safe {
		return domain.ErrConflict
	}
	return nil
}
