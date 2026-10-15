package postgres

import (
	"context"
	"errors"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

// Load is an internal configuration read, not an authenticated administrator API.
func (r *Repository) Load(ctx context.Context) (domain.Snapshot, error) {
	return scanSnapshot(r.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton`))
}

func (r *Repository) Read(ctx context.Context, actor accessservice.Principal) (domain.Snapshot, error) {
	result, err := scanSnapshot(r.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton AND EXISTS(
		SELECT 1 FROM auth.sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
		WHERE u.id=$1 AND s.token_hash=$2 AND u.status='active' AND u.deleted_at IS NULL
		AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()
		AND EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=u.id AND rp.permission_key=$3)
	)`, actor.UserID, actor.TokenHash, settings.AuthSettingsManage))
	if errors.Is(err, domain.ErrNotInitialized) {
		return domain.Snapshot{}, accessdomain.ErrForbidden
	}
	return result, err
}
