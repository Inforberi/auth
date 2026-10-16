package postgres

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func (r *Repository) Update(ctx context.Context, input service.UpdateInput) (domain.Snapshot, error) {
	var result domain.Snapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage); err != nil {
			return err
		}
		before, err := scanSnapshot(tx.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton FOR UPDATE`))
		if err != nil {
			return err
		}
		if before.Version != input.ExpectedVersion {
			return domain.ErrPolicyConflict
		}
		if !r.runtimeConfigured {
			return domain.ErrMethodNotReady
		}
		if err := input.Policy.RequireAvailable(r.available); err != nil {
			return err
		}
		if before.Policy == input.Policy {
			result = before
			return nil
		}
		result, err = scanSnapshot(tx.QueryRow(ctx, `UPDATE auth.auth_settings SET version=version+1,
			password_enabled=$1,email_otp_enabled=$2,google_enabled=$3,telegram_enabled=$4,
			registration_enabled=$5,google_registration_enabled=$6,telegram_registration_enabled=$7,password_email_verification=$8
			WHERE singleton RETURNING `+policyColumns, policyValues(input.Policy)...))
		if err != nil {
			return err
		}
		previous, err := json.Marshal(before.Policy)
		if err != nil {
			return err
		}
		next, err := json.Marshal(input.Policy)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.auth_settings_audit(actor_id,version,previous_policy,next_policy) VALUES($1,$2,$3,$4)`, input.Actor.UserID, result.Version, previous, next)
		return err
	})
	if err != nil {
		return domain.Snapshot{}, err
	}
	return result, nil
}
