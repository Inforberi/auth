package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func (r *Repository) UpdateRetention(ctx context.Context, input service.RetentionUpdateInput) (domain.RetentionSnapshot, error) {
	var result domain.RetentionSnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage); err != nil {
			return err
		}
		before, err := scanRetention(tx.QueryRow(ctx, `SELECT `+retentionColumns+` FROM auth.retention_settings WHERE singleton FOR UPDATE`))
		if err != nil {
			return err
		}
		if before.Version != input.ExpectedVersion {
			return domain.ErrPolicyConflict
		}
		if input.Policy.Shortens(before.Policy) && !input.ConfirmShortening {
			return domain.ErrRetentionConfirmation
		}
		if before.Policy == input.Policy {
			result = before
			return nil
		}
		p := input.Policy
		result, err = scanRetention(tx.QueryRow(ctx, `UPDATE auth.retention_settings SET version=version+1,
			email_reservation_days=$1,session_days=$2,security_audit_days=$3 WHERE singleton RETURNING `+retentionColumns,
			p.EmailReservationDays, p.SessionDays, p.SecurityAuditDays))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.retention_settings_audit(actor_id,version,previous_configuration,next_configuration)
			VALUES($1,$2,$3,$4)`, input.Actor.UserID, result.Version, before, result)
		return err
	})
	return result, err
}
