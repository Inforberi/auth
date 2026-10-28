package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

// The caller holds Access then user locks. Enrolled factor checks/consumption remain with the MFA caller.
func AdministrativePasswordAllowed(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, hash string) (bool, error) {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_credentials p
		JOIN auth.user_emails e ON e.id=p.email_id AND e.user_id=p.user_id
		WHERE p.user_id=$1 AND p.password_hash=$2 AND e.verified_at IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND (activated_at IS NULL OR password_change_required))
		AND auth.has_administrative_access($1))`, user, hash).Scan(&allowed)
	return allowed, err
}
