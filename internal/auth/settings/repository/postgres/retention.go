package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

const retentionColumns = `version,email_reservation_days,session_days,security_audit_days`

func scanRetention(row pgx.Row) (domain.RetentionSnapshot, error) {
	var s domain.RetentionSnapshot
	err := row.Scan(&s.Version, &s.Policy.EmailReservationDays, &s.Policy.SessionDays, &s.Policy.SecurityAuditDays)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, domain.ErrNotInitialized
	}
	return s, err
}

func (r *Repository) LoadRetention(ctx context.Context) (domain.RetentionSnapshot, error) {
	return scanRetention(r.db.QueryRow(ctx, `SELECT `+retentionColumns+` FROM auth.retention_settings WHERE singleton`))
}

func (r *Repository) ReadRetention(ctx context.Context, actor accessservice.Principal) (domain.RetentionSnapshot, error) {
	s, err := scanRetention(r.db.QueryRow(ctx, `SELECT `+retentionColumns+` FROM auth.retention_settings WHERE singleton AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage))
	if errors.Is(err, domain.ErrNotInitialized) {
		return s, accessdomain.ErrForbidden
	}
	return s, err
}

func (r *Repository) InitializeRetention(ctx context.Context, seed domain.RetentionPolicy) (domain.RetentionSnapshot, error) {
	var result domain.RetentionSnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		stored, err := scanRetention(tx.QueryRow(ctx, `SELECT `+retentionColumns+` FROM auth.retention_settings WHERE singleton FOR UPDATE`))
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
		result, err = scanRetention(tx.QueryRow(ctx, `INSERT INTO auth.retention_settings(singleton,email_reservation_days,session_days,security_audit_days)
			VALUES(true,$1,$2,$3) RETURNING `+retentionColumns, seed.EmailReservationDays, seed.SessionDays, seed.SecurityAuditDays))
		return err
	})
	return result, err
}
