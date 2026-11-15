package managementaudit

import (
	"context"

	"github.com/jackc/pgx/v5"

	account "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func Record(ctx context.Context, tx pgx.Tx, actor account.UserID, action, target string, before, after any) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth.platform_management_audit(actor_id,action,target,previous_value,next_value)
		VALUES($1,$2,$3,$4::jsonb,$5::jsonb)`, actor, action, target, before, after)
	return err
}
