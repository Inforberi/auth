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
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

const smtpColumns = `version,configuration,password_set`

func scanSMTP(row pgx.Row, secret bool) (service.SMTPStored, error) {
	var s service.SMTPStored
	values := []any{&s.Version, &s.Config, &s.PasswordSet}
	if secret {
		values = append(values, &s.Password)
	}
	err := row.Scan(values...)
	if errors.Is(err, pgx.ErrNoRows) {
		return service.SMTPStored{}, domain.ErrNotInitialized
	}
	return s, err
}

func (r *Repository) LoadSMTP(ctx context.Context) (service.SMTPStored, error) {
	return scanSMTP(r.db.QueryRow(ctx, `SELECT `+smtpColumns+`,password FROM auth.smtp_settings WHERE singleton`), true)
}

func (r *Repository) ReadSMTP(ctx context.Context, actor accessservice.Principal) (domain.SMTPSnapshot, error) {
	stored, err := scanSMTP(r.db.QueryRow(ctx, `SELECT `+smtpColumns+` FROM auth.smtp_settings WHERE singleton AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage), false)
	if errors.Is(err, domain.ErrNotInitialized) {
		return domain.SMTPSnapshot{}, accessdomain.ErrForbidden
	}
	return stored.SMTPSnapshot, err
}

func (r *Repository) InitializeSMTP(ctx context.Context, seed service.SMTPStored) (service.SMTPStored, error) {
	var result service.SMTPStored
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		stored, err := scanSMTP(tx.QueryRow(ctx, `SELECT `+smtpColumns+`,password FROM auth.smtp_settings WHERE singleton FOR UPDATE`), true)
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
		result, err = scanSMTP(tx.QueryRow(ctx, `INSERT INTO auth.smtp_settings(singleton,configuration,password,password_set)
			VALUES(true,$1,$2,$3) RETURNING `+smtpColumns+`,password`, seed.Config, seed.Password, seed.PasswordSet), true)
		return err
	})
	return result, err
}
