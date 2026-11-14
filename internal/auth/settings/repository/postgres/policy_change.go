package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func CheckPolicyChange(ctx context.Context, tx pgx.Tx, before domain.Snapshot, expected int64, next domain.Policy, runtime domain.PolicyRuntime) error {
	if err := RequireAPISettings(ctx, tx); err != nil {
		return err
	}
	if err := runtime.CheckChange(before, expected, next); err != nil {
		return err
	}
	if runtime.Dependencies != nil {
		if err := checkDependencyVersions(ctx, tx, next, *runtime.Dependencies); err != nil {
			return err
		}
	}
	return checkStoredPolicyDependencies(ctx, tx, next, runtime.RequireStoredProviders)
}

// ApplyPolicyChange owns no authority or audit: caller holds the Access/policy locks.
func ApplyPolicyChange(ctx context.Context, tx pgx.Tx, next domain.Policy) (domain.Snapshot, error) {
	return scanSnapshot(tx.QueryRow(ctx, `UPDATE auth.auth_settings SET version=version+1,
		password_enabled=$1,email_otp_enabled=$2,google_enabled=$3,telegram_enabled=$4,
		registration_enabled=$5,google_registration_enabled=$6,telegram_registration_enabled=$7,password_email_verification=$8,
		token_session_exchange_enabled=$9,token_native_enabled=$10 WHERE singleton RETURNING `+policyColumns, policyValues(next)...))
}

func checkStoredPolicyDependencies(ctx context.Context, tx pgx.Tx, policy domain.Policy, requireStored bool) error {
	var ready bool
	err := tx.QueryRow(ctx, `SELECT (CASE WHEN $3 OR EXISTS(SELECT 1 FROM auth.provider_settings)
		OR EXISTS(SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NOT NULL)
		THEN (NOT $1 OR EXISTS(SELECT 1 FROM auth.provider_settings WHERE provider='google' AND client_id<>'' AND secret_set))
		AND (NOT $2 OR EXISTS(SELECT 1 FROM auth.provider_settings WHERE provider='telegram' AND client_id<>'' AND secret_set))
		ELSE true END) AND (NOT $4 OR EXISTS(SELECT 1 FROM auth.smtp_settings))`, policy.Methods.Google, policy.Methods.Telegram, requireStored, requireStored && policy.RequiresEmailDelivery()).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return domain.ErrMethodNotReady
	}
	return nil
}
