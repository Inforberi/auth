package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

// LockPublicPolicy follows all account/identity locks; callers must not lock another user afterwards.
// Shared readers serialize only with policy changes, not with other public logins.
func LockPublicPolicy(ctx context.Context, tx pgx.Tx) (domain.Policy, error) {
	snapshot, err := scanSnapshot(tx.QueryRow(ctx, `SELECT `+policyColumns+` FROM auth.auth_settings WHERE singleton FOR SHARE`))
	if err != nil {
		return domain.Policy{}, fmt.Errorf("%w: %w", domain.ErrPolicyUnavailable, err)
	}
	return snapshot.Policy, nil
}

func RequirePublicLogin(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, method, issuer string) error {
	policy, err := LockPublicPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if err := policy.RequireMethod(domain.PrimaryMethod(method, issuer), false); err != nil {
		return err
	}
	if method == "password" && policy.PasswordEmailVerification == domain.VerificationRequired {
		var verified bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_credentials p JOIN auth.user_emails e
			ON e.user_id=p.user_id AND e.id=p.email_id WHERE p.user_id=$1 AND e.verified_at IS NOT NULL)`, user).Scan(&verified); err != nil {
			return err
		}
		if !verified {
			return accountdomain.ErrEmailUnverified
		}
	}
	return nil
}
