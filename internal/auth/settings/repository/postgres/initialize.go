package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (r *Repository) Initialize(ctx context.Context, initial domain.Policy) (domain.Snapshot, error) {
	var result domain.Snapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		stored, err := scanSnapshot(tx.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton FOR UPDATE`))
		if err == nil {
			result = stored
			return nil
		}
		if !errors.Is(err, domain.ErrNotInitialized) {
			return err
		}
		var initialized bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NOT NULL)`).Scan(&initialized); err != nil {
			return err
		}
		if initialized {
			return domain.ErrNotInitialized
		}
		result, err = scanSnapshot(tx.QueryRow(ctx, `INSERT INTO auth.auth_settings(singleton,password_enabled,email_otp_enabled,google_enabled,telegram_enabled,
			registration_enabled,google_registration_enabled,telegram_registration_enabled,password_email_verification)
			VALUES(true,$1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+policyColumns, policyValues(initial)...))
		return err
	})
	if err != nil {
		return domain.Snapshot{}, err
	}
	return result, nil
}
