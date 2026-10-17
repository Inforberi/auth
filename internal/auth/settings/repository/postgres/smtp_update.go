package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func (r *Repository) UpdateSMTP(ctx context.Context, input service.SMTPUpdate) (domain.SMTPSnapshot, error) {
	var result domain.SMTPSnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage); err != nil {
			return err
		}
		before, err := scanSMTP(tx.QueryRow(ctx, `SELECT `+smtpColumns+`,password FROM auth.smtp_settings WHERE singleton FOR UPDATE`), true)
		if err != nil {
			return err
		}
		if before.Version != input.ExpectedVersion {
			return domain.ErrPolicyConflict
		}
		password, passwordSet := input.Password, input.PasswordSet
		if password == nil {
			// Do not silently send retained credentials to a different server or identity.
			if before.Config.Host != input.Config.Host || before.Config.Port != input.Config.Port || before.Config.Username != input.Config.Username {
				return domain.ErrInvalidSMTP
			}
			password, passwordSet = before.Password, before.PasswordSet
		}
		if input.Config.Username != "" && !passwordSet {
			return domain.ErrInvalidSMTP
		}
		if input.Password == nil && before.Config == input.Config {
			result = before.SMTPSnapshot
			return nil
		}
		stored, err := scanSMTP(tx.QueryRow(ctx, `UPDATE auth.smtp_settings SET version=version+1,configuration=$1,password=$2,password_set=$3
			WHERE singleton RETURNING `+smtpColumns, input.Config, password, passwordSet), false)
		if err != nil {
			return err
		}
		result = stored.SMTPSnapshot
		_, err = tx.Exec(ctx, `INSERT INTO auth.smtp_settings_audit(actor_id,version,previous_configuration,next_configuration)
			VALUES($1,$2,$3,$4)`, input.Actor.UserID, result.Version, before.SMTPSnapshot, result)
		return err
	})
	return result, err
}

func (r *Repository) AuthorizeSMTPTest(ctx context.Context, actor accessservice.Principal, version int64) (service.SMTPStored, error) {
	var result service.SMTPStored
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, actor, "", settings.AuthSettingsManage); err != nil {
			return err
		}
		stored, err := scanSMTP(tx.QueryRow(ctx, `SELECT `+smtpColumns+`,password FROM auth.smtp_settings WHERE singleton FOR SHARE`), true)
		if err != nil {
			return err
		}
		if stored.Version != version {
			return domain.ErrPolicyConflict
		}
		result = stored
		return nil
	})
	return result, err
}
