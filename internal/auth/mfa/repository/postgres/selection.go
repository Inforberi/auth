package postgres

import (
	"context"
	"errors"

	pgx "github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) ReadMethodSelection(ctx context.Context, proof mfaservice.PrimaryProof) (domain.MethodSelection, error) {
	var state domain.MethodSelection
	err := r.db.QueryRow(ctx, `SELECT COALESCE(p.preferred_method,''),
 EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=u.id),auth.email_factor_usable(u.id),auth.telegram_factor_usable(u.id),
 auth.has_administrative_access(u.id),EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=u.id) OR EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=u.id) FROM auth.users u LEFT JOIN auth.mfa_preferences p ON p.user_id=u.id
 WHERE u.id=$1 AND u.auth_version=$2 AND u.status='active' AND u.deleted_at IS NULL`, proof.UserID, proof.AuthVersion).Scan(&state.Preferred, &state.TOTP, &state.Email, &state.Telegram, &state.Administrative, &state.ConfiguredWeak)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, domain.ErrProofRequired
	}
	return state, err
}
