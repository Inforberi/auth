package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
)

const operatorReadGuard = `EXISTS(
		SELECT 1 FROM platform.operator_realm realm
		JOIN platform.operator_permissions p ON p.user_id=$2 AND p.permission_key=$4
		JOIN auth.users u ON u.id=p.user_id
		JOIN auth.role_bound_sessions s ON s.user_id=u.id AND s.token_hash=$3
		WHERE realm.id=$1 AND realm.initialized_at IS NOT NULL
		AND u.status='active' AND u.deleted_at IS NULL AND s.auth_version=u.auth_version
		AND s.credential_profile='browser' AND s.primary_method='password'
		AND s.password_verified_at<=clock_timestamp()
		AND (NOT auth.mfa_login_required(u.id,true) OR (s.strong_mfa_verified_at<=clock_timestamp()
			AND EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=u.id)))
		AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
		AND EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=u.id)
	)`

// AuthorizeRead is a current SQL snapshot, not a mutation/bridge guard.
// Mutations must hold authority locks through their commit; a preceding read is insufficient.
func (r *Repository) AuthorizeRead(ctx context.Context, actor domain.Principal, permission domain.Permission) error {
	if !permission.Valid() || !actor.Valid() {
		return domain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var allowed bool
	err := r.db.QueryRow(ctx, `SELECT `+operatorReadGuard, r.realm, actor.UserID, actor.TokenHash, permission).Scan(&allowed)
	if err != nil {
		return errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	if !allowed {
		return domain.ErrForbidden
	}
	return nil
}
