package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (r *Repository) CheckDisabled(ctx context.Context) error {
	return r.CheckCapability(ctx, false)
}

// CheckCapability validates assembly readiness; session issuance still checks current SQL authority.
func (r *Repository) CheckCapability(ctx context.Context, enabled bool) error {
	var policy settingsdomain.MFAPolicy
	var compatible bool
	err := r.db.QueryRow(ctx, `SELECT p.mode,NOT p.email_factor_allowed AND NOT EXISTS(SELECT 1 FROM auth.mfa_email) AND ($1::boolean OR NOT (
 EXISTS(SELECT 1 FROM auth.mfa_totp) OR EXISTS(SELECT 1 FROM auth.roles WHERE mfa_required)
 OR p.mode='required' OR p.mode='administrators'
 AND EXISTS(SELECT 1 FROM auth.roles r WHERE EXISTS(SELECT 1 FROM auth.user_roles WHERE role_id=r.id)
  AND ((r.system AND r.key='super_admin') OR EXISTS(SELECT 1 FROM auth.role_permissions rp WHERE rp.role_id=r.id
   AND rp.permission_key IN ('access.roles.manage','access.assignments.manage','accounts.email.bind','accounts.users.manage',
    'accounts.users.status.manage','accounts.users.delete','auth.settings.manage')))))
  ) FROM auth.mfa_settings p WHERE singleton AND version>0`, enabled).Scan(&policy.Mode, &compatible)
	if errors.Is(err, pgx.ErrNoRows) {
		return settingsdomain.ErrNotInitialized
	}
	if err != nil {
		return err
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	if !compatible {
		return errors.New("MFA runtime is incompatible with stored factors or policy")
	}
	return nil
}
