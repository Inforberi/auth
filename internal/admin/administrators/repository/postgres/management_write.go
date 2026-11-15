package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	provisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
)

func applyOperatorManagement(ctx context.Context, tx pgx.Tx, actor domain.Principal, input domain.Management, invite provisioning.ProvisionCommand) (accountdomain.UserID, error) {
	user := input.UserID
	if input.Action == "invite" {
		var err error
		user, err = accountpostgres.ProvisionAuthorizedInvitation(ctx, tx, invite, actor.UserID, string(input.OperationID))
		if err != nil {
			return "", err
		}
	} else {
		if user == actor.UserID {
			return "", domain.ErrOwnerProtected
		}
		deleted, err := tx.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1`, user)
		if err != nil {
			return "", err
		}
		if deleted.RowsAffected() == 0 {
			return "", domain.ErrOperatorConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.users SET auth_version=auth_version+CASE WHEN status='pending' AND $2='permissions' THEN 0 ELSE 1 END,
			status=CASE WHEN $2='revoke' THEN 'blocked' ELSE status END WHERE id=$1`, user, input.Action); err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, user); err != nil {
			return "", err
		}
		if input.Action == "revoke" {
			if _, err := tx.Exec(ctx, `DELETE FROM auth.account_invitations WHERE user_id=$1`, user); err != nil {
				return "", err
			}
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key)
		SELECT $1,unnest($2::text[])`, user, input.Permissions); err != nil {
		return "", err
	}
	_, err := tx.Exec(ctx, `INSERT INTO platform.operator_management(operation_id,actor_id,user_id,action,permissions,fingerprint)
		VALUES($1,$2,$3,$4,$5,$6)`, input.OperationID, actor.UserID, user, input.Action, input.Permissions, invite.Fingerprint)
	return user, err
}
