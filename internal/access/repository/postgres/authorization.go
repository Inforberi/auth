package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
)

// AuthorizeMutation shares the SQL lock/proof/permission guard with other feature transactions.
// Call it before taking any user/session/intent locks; the caller owns commit and rollback.
func AuthorizeMutation(ctx context.Context, tx pgx.Tx, actor service.Principal, target string, permission domain.PermissionKey) (time.Time, error) {
	if err := LockAccessChanges(ctx, tx); err != nil {
		return time.Time{}, err
	}
	deadline, err := lockActor(ctx, tx, actor, target)
	if err != nil {
		return time.Time{}, err
	}
	if err := requireDelegation(ctx, tx, actor, permission, nil); err != nil {
		return time.Time{}, err
	}
	return deadline, nil
}
