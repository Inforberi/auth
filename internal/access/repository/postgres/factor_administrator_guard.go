package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func requireNonTOTPAdministrativeFactor(ctx context.Context, tx pgx.Tx, user accountdomain.UserID) error {
	var incompatible bool
	err := tx.QueryRow(ctx, `SELECT (EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1)
 OR EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=$1))
 AND auth.has_administrative_access($1) AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, user).Scan(&incompatible)
	if err != nil {
		return err
	}
	if incompatible {
		return domain.ErrConflict
	}
	return nil
}

func requireRoleNonTOTPAdministrativeFactor(ctx context.Context, tx pgx.Tx, role domain.RoleID) error {
	var incompatible bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.user_roles ur
 WHERE ur.role_id=$1 AND auth.has_administrative_access(ur.user_id)
 AND (EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=ur.user_id)
  OR EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=ur.user_id))
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=ur.user_id))`, role).Scan(&incompatible)
	if err != nil {
		return err
	}
	if incompatible {
		return domain.ErrConflict
	}
	return nil
}
