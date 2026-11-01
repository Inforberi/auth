package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) SelectMFAMethod(ctx context.Context, proof service.PrimaryProof) (domain.Method, error) {
	var selected domain.Method
	var totp, email, telegram, administrative, configuredWeak bool
	err := r.db.QueryRow(ctx, `SELECT COALESCE(p.preferred_method,''),
 EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=u.id),auth.email_factor_usable(u.id),auth.telegram_factor_usable(u.id),
 auth.has_administrative_access(u.id),EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=u.id) OR EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=u.id) FROM auth.users u LEFT JOIN auth.mfa_preferences p ON p.user_id=u.id
 WHERE u.id=$1 AND u.auth_version=$2 AND u.status='active' AND u.deleted_at IS NULL`, proof.UserID, proof.AuthVersion).Scan(&selected, &totp, &email, &telegram, &administrative, &configuredWeak)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrProofRequired
	}
	if err != nil {
		return "", err
	}
	if proof.Administrative || administrative || proof.Method != "password" {
		return domain.TOTP, nil
	}
	if selected != "" {
		if selected == domain.TOTP && totp || selected == domain.EmailCode && email || selected == domain.TelegramCode && telegram {
			return selected, nil
		}
		return "", domain.ErrUnavailable
	}
	if totp {
		return domain.TOTP, nil
	}
	if email {
		return domain.EmailCode, nil
	}
	if telegram {
		return domain.TelegramCode, nil
	}
	if configuredWeak {
		return "", domain.ErrUnavailable
	}
	// Existing required enrollment / explicitly requested assisted recovery still owns this path.
	return domain.TOTP, nil
}
