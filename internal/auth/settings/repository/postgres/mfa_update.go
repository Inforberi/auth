package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func (r *Repository) UpdateMFAPolicy(ctx context.Context, input service.MFAUpdateInput, ready bool) (domain.MFASnapshot, error) {
	var result domain.MFASnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage); err != nil {
			return err
		}
		var err error
		result, err = ApplyMFAPolicyChange(ctx, tx, input.Actor.UserID, input.MFAChange, ready)
		return err
	})
	if err != nil {
		return domain.MFASnapshot{}, err
	}
	return result, nil
}

// ApplyMFAPolicyChange requires caller-owned Access and actor authority locks through commit.
// It persists configuration only; publishing optional flows requires the complete MFA enforcement stage.
func ApplyMFAPolicyChange(ctx context.Context, tx pgx.Tx, actor accountdomain.UserID, input service.MFAChange, ready bool) (domain.MFASnapshot, error) {
	return ApplyMFAPolicy(ctx, tx, input, ready, func(before, after domain.MFASnapshot) error {
		_, err := tx.Exec(ctx, `INSERT INTO auth.mfa_settings_audit(actor_id,version,previous_configuration,next_configuration)
			VALUES($1,$2,$3,$4)`, actor, after.Version, before, after)
		return err
	})
}

func ApplyMFAPolicy(ctx context.Context, tx pgx.Tx, input service.MFAChange, ready bool, audit func(domain.MFASnapshot, domain.MFASnapshot) error) (domain.MFASnapshot, error) {
	if err := RequireAPISettings(ctx, tx); err != nil {
		return domain.MFASnapshot{}, err
	}
	if err := input.Policy.ValidateChange(input.ExpectedVersion); err != nil {
		return domain.MFASnapshot{}, err
	}
	before, err := scanMFA(tx.QueryRow(ctx, `SELECT `+mfaColumns+` FROM auth.mfa_settings WHERE singleton FOR UPDATE`))
	if err != nil {
		return domain.MFASnapshot{}, err
	}
	changed, err := before.CheckChange(input.ExpectedVersion, input.Policy, ready)
	if err != nil {
		return domain.MFASnapshot{}, err
	}
	if !changed {
		return before, nil
	}
	result, err := scanMFA(tx.QueryRow(ctx, `UPDATE auth.mfa_settings SET mode=$1,version=version+1,
		session_revision=session_revision+CASE WHEN $2 THEN 1 ELSE 0 END
		WHERE singleton RETURNING `+mfaColumns, input.Policy.Mode, input.Policy.Strengthens(before.Policy)))
	if err != nil {
		return domain.MFASnapshot{}, err
	}
	return result, audit(before, result)
}
