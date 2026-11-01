package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func requireEmailAdministrativeFactor(ctx context.Context, tx pgx.Tx, user accountdomain.UserID) error {
	var incompatible bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_email e WHERE e.user_id=$1
 AND auth.has_administrative_access(e.user_id) AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=e.user_id))`, user).Scan(&incompatible)
	if err != nil {
		return err
	}
	if incompatible {
		return domain.ErrConflict
	}
	return nil
}

func requireRoleEmailAdministrativeFactor(ctx context.Context, tx pgx.Tx, role domain.RoleID) error {
	var incompatible bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.mfa_email e ON e.user_id=ur.user_id
 WHERE ur.role_id=$1 AND auth.has_administrative_access(e.user_id)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=e.user_id))`, role).Scan(&incompatible)
	if err != nil {
		return err
	}
	if incompatible {
		return domain.ErrConflict
	}
	return nil
}
