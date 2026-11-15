package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsretention "github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/service"
)

func (r *Repository) UpdateRetention(ctx context.Context, input settingsretention.RetentionUpdateInput) (domain.RetentionSnapshot, error) {
	var result domain.RetentionSnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage); err != nil {
			return err
		}
		var returnErr error
		result, returnErr = ApplyRetention(ctx, tx, input, func(before, after domain.RetentionSnapshot) error {
			_, err := tx.Exec(ctx, `INSERT INTO auth.retention_settings_audit(actor_id,version,previous_configuration,next_configuration)
        VALUES($1,$2,$3,$4)`, input.Actor.UserID, after.Version, before, after)
			return err
		})
		return returnErr
	})
	return result, err
}

func ApplyRetention(ctx context.Context, tx pgx.Tx, input settingsretention.RetentionUpdateInput, audit func(domain.RetentionSnapshot, domain.RetentionSnapshot) error) (domain.RetentionSnapshot, error) {
	var result domain.RetentionSnapshot
	if err := RequireAPISettings(ctx, tx); err != nil {
		return result, err
	}
	before, err := scanRetention(tx.QueryRow(ctx, `SELECT `+retentionColumns+` FROM auth.retention_settings WHERE singleton FOR UPDATE`))
	if err != nil {
		return result, err
	}
	if before.Version != input.ExpectedVersion {
		return result, domain.ErrPolicyConflict
	}
	if input.Policy.Shortens(before.Policy) && !input.ConfirmShortening {
		return result, domain.ErrRetentionConfirmation
	}
	if before.Policy == input.Policy {
		return before, nil
	}
	p := input.Policy
	result, err = scanRetention(tx.QueryRow(ctx, `UPDATE auth.retention_settings SET version=version+1,
			email_reservation_days=$1,session_days=$2,security_audit_days=$3 WHERE singleton RETURNING `+retentionColumns,
		p.EmailReservationDays, p.SessionDays, p.SecurityAuditDays))
	if err != nil {
		return result, err
	}
	return result, audit(before, result)
}
