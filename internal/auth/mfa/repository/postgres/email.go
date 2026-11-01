package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) ReadEmailFactor(ctx context.Context, proof service.Proof) (*domain.EmailFactor, error) {
	var result domain.EmailFactor
	err := r.db.QueryRow(ctx, `SELECT p.email_factor_allowed,f.user_id IS NOT NULL,
 COALESCE(f.email_id::text,''),f.enabled_at,f.suspended_at,
 auth.email_factor_usable(u.id)
 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
 CROSS JOIN auth.mfa_settings p LEFT JOIN auth.mfa_email f ON f.user_id=u.id
 WHERE p.singleton AND s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3
 AND u.status='active' AND u.deleted_at IS NULL AND s.credential_profile='browser'
 AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()`,
		proof.UserID, proof.TokenHash, proof.AuthVersion).Scan(&result.Allowed, &result.Configured,
		&result.EmailID, &result.EnabledAt, &result.SuspendedAt, &result.Usable)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrProofRequired
	}
	if err != nil {
		return nil, err
	}
	return &result, nil
}
