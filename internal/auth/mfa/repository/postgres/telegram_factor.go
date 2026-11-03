package postgres

import (
	"context"
	"errors"

	pgx "github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) ReadTelegramFactor(ctx context.Context, proof mfaservice.Proof) (*domain.TelegramFactor, error) {
	var result domain.TelegramFactor
	err := r.db.QueryRow(ctx, `SELECT p.telegram_factor_allowed,f.user_id IS NOT NULL,
 COALESCE(f.bot_id,0),COALESCE(f.telegram_user_id,0),f.enabled_at
 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
 CROSS JOIN auth.mfa_settings p LEFT JOIN auth.mfa_telegram f ON f.user_id=u.id
 WHERE p.singleton AND s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3
 AND u.status='active' AND u.deleted_at IS NULL AND s.credential_profile='browser'
 AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()`,
		proof.UserID, proof.TokenHash, proof.AuthVersion).Scan(&result.Allowed, &result.Configured, &result.BotID, &result.TelegramID, &result.EnabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrProofRequired
	}
	if err != nil {
		return nil, err
	}
	return &result, nil
}
