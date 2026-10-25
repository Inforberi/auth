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
		before, err := LockPolicyInTransaction(ctx, tx)
		if err != nil {
			return err
		}
		if err := CheckPolicyChange(ctx, tx, before, input.ExpectedVersion, input.Policy, r.runtime); err != nil {
			return err
		}
		if before.Policy == input.Policy {
			result = before
			return nil
		}
		if input.Policy.RestrictsLogin(before.Policy) {
			if err := accesspostgres.RequireUsableAdministrator(ctx, tx); err != nil {
				return err
			}
		}
		result, err = ApplyPolicyChange(ctx, tx, input.Policy)
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
