package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	configuration "github.com/Inforberi/financial-intelligence/internal/auth/settings/configuration/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

// Load is an internal configuration read, not an authenticated administrator API.
func (r *Repository) Load(ctx context.Context) (domain.Snapshot, error) {
	return scanSnapshot(r.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton`))
}

// Transaction readers expose persistence only; their caller owns authority and binding.
func ReadPolicyInTransaction(ctx context.Context, tx pgx.Tx) (domain.Snapshot, error) {
	return scanSnapshot(tx.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton`))
}

func LockPolicyInTransaction(ctx context.Context, tx pgx.Tx) (domain.Snapshot, error) {
	return scanSnapshot(tx.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton FOR UPDATE`))
}

const settingsReadGuard = `EXISTS(
		SELECT 1 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
		WHERE u.id=$1 AND s.token_hash=$2 AND u.status='active' AND u.deleted_at IS NULL
		AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()
		AND EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=u.id AND rp.permission_key=$3)
	)`

func (r *Repository) Read(ctx context.Context, actor accessservice.Principal) (domain.Snapshot, error) {
	result, err := scanSnapshot(r.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage))
	if errors.Is(err, domain.ErrNotInitialized) {
		return domain.Snapshot{}, accessdomain.ErrForbidden
	}
	if err == nil {
		err = r.db.QueryRow(ctx, `SELECT mode FROM auth.settings_source WHERE singleton`).Scan(&result.Source)
	}
	if result.Source == domain.SourceAPI {
		result.Source = ""
	}
	if err == nil && configuration.EnvironmentOwned(ctx) {
		result.Source = domain.SourceENV
	}
	return result, err
}
