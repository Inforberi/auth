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
	if input.ExpectedVersion < 1 || input.Policy.Validate() != nil {
		return domain.MFASnapshot{}, domain.ErrInvalidMFAPolicy
	}
	before, err := scanMFA(tx.QueryRow(ctx, `SELECT `+mfaColumns+` FROM auth.mfa_settings WHERE singleton FOR UPDATE`))
	if err != nil {
		return domain.MFASnapshot{}, err
	}
	if before.Version != input.ExpectedVersion {
		return domain.MFASnapshot{}, domain.ErrPolicyConflict
	}
	if before.Policy == input.Policy {
		return before, nil
	}
	if input.Policy.Mode != domain.MFAOptional && !ready {
		return domain.MFASnapshot{}, domain.ErrMethodNotReady
	}
	result, err := scanMFA(tx.QueryRow(ctx, `UPDATE auth.mfa_settings SET mode=$1,version=version+1,
		session_revision=session_revision+CASE WHEN $2 THEN 1 ELSE 0 END
		WHERE singleton RETURNING `+mfaColumns, input.Policy.Mode, input.Policy.Strengthens(before.Policy)))
	if err != nil {
		return domain.MFASnapshot{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.mfa_settings_audit(actor_id,version,previous_configuration,next_configuration)
		VALUES($1,$2,$3,$4)`, actor, result.Version, before, result)
	return result, err
}
