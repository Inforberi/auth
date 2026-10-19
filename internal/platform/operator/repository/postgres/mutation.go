package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
)

// AuthorizeMutation joins a caller-owned Read Committed transaction, before project locks.
// Current platform policy requires password + TOTP; optional MFA remains closed until A6.3m.
func (r *Repository) AuthorizeMutation(ctx context.Context, tx pgx.Tx, actor domain.Principal, permission domain.Permission, freshFor time.Duration) (time.Time, error) {
	if !actor.Valid() || !permission.Valid() {
		return time.Time{}, domain.ErrForbidden
	}
	if tx == nil || freshFor < time.Minute || freshFor > 15*time.Minute {
		return time.Time{}, domain.ErrUnavailable
	}
	if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
		return time.Time{}, mutationError(ctx, err)
	}
	// Shared locks protect revocation without serializing independent project commands.
	for _, lock := range []struct {
		sql  string
		args []any
	}{
		{`SELECT 1 FROM platform.operator_realm WHERE id=$1 AND initialized_at IS NOT NULL FOR SHARE`, []any{r.realm}},
		{`SELECT 1 FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, []any{actor.UserID}},
		{`SELECT 1 FROM platform.operator_permissions WHERE user_id=$1 AND permission_key=$2 FOR SHARE`, []any{actor.UserID, permission}},
	} {
		var found int
		if err := tx.QueryRow(ctx, lock.sql, lock.args...).Scan(&found); err != nil {
			return time.Time{}, mutationError(ctx, err)
		}
	}
	var deadline time.Time
	err := tx.QueryRow(ctx, `SELECT LEAST(s.expires_at,s.absolute_expires_at,
		s.password_verified_at+$3::double precision*interval '1 second',s.mfa_verified_at+interval '5 minutes')
		FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
		JOIN auth.password_credentials p ON p.user_id=s.user_id
		JOIN auth.mfa_totp m ON m.user_id=s.user_id
		WHERE s.user_id=$1 AND s.token_hash=$2 AND s.credential_profile='browser' AND s.primary_method='password'
		AND s.password_verified_at<=clock_timestamp() AND s.mfa_verified_at<=clock_timestamp()
		AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
		FOR SHARE OF s,p,m`, actor.UserID, actor.TokenHash, freshFor.Seconds()).Scan(&deadline)
	if err != nil {
		return time.Time{}, mutationError(ctx, err)
	}
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
		return time.Time{}, mutationError(ctx, err)
	}
	if !fresh {
		return time.Time{}, domain.ErrFreshAuthRequired
	}
	return deadline, nil
}

func mutationError(ctx context.Context, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrForbidden
	}
	return errors.Join(domain.ErrUnavailable, ctx.Err())
}
