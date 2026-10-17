package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (r *Repository) RequireIdentityFreshAuth(ctx context.Context, user domain.UserID, token string, freshFor time.Duration) error {
	var valid bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id
		JOIN auth.password_credentials p ON p.user_id=u.id
		JOIN auth.user_emails e ON e.id=p.email_id AND e.user_id=p.user_id
		WHERE u.id=$1 AND u.status='active' AND u.deleted_at IS NULL AND s.token_hash=$2
		AND e.verified_at IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND activated_at IS NULL)
		AND s.auth_version=u.auth_version AND s.revoked_at IS NULL
		AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
		AND s.password_verified_at<=clock_timestamp()
		AND s.password_verified_at>clock_timestamp()-$3::double precision*interval '1 second')`, user, token, freshFor.Seconds()).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid || freshFor <= 0 {
		return domain.ErrFreshAuthRequired
	}
	return nil
}

func lockIdentitySession(ctx context.Context, tx pgx.Tx, user domain.UserID, token string, freshFor time.Duration) (domain.AuthVersion, error) {
	if freshFor <= 0 {
		return 0, domain.ErrFreshAuthRequired
	}
	var version domain.AuthVersion
	err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR UPDATE`, user).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.ErrFreshAuthRequired
	}
	if err != nil {
		return 0, err
	}
	if err := requireSessionProof(ctx, tx, user, token, version, freshFor); err != nil {
		return 0, err
	}
	return version, nil
}

func (r *Repository) LinkIdentity(ctx context.Context, user domain.UserID, token string, key domain.IdentityKey, freshFor time.Duration) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		version, err := lockIdentitySession(ctx, tx, user, token, freshFor)
		if err != nil {
			return err
		}
		valid, err := hasPermanentPassword(ctx, tx, user)
		if err != nil {
			return err
		}
		if !valid {
			return domain.ErrFreshAuthRequired
		}
		var owner domain.UserID
		err = tx.QueryRow(ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id) VALUES ($1,$2,$3)
			ON CONFLICT DO NOTHING RETURNING user_id`, key.Issuer, key.Subject, user).Scan(&owner)
		created := err == nil
		if errors.Is(err, pgx.ErrNoRows) {
			// Both exact identity ownership and one identity per provider are protected by UNIQUE.
			err = tx.QueryRow(ctx, `SELECT user_id FROM auth.linked_identities WHERE issuer=$1 AND subject=$2`, key.Issuer, key.Subject).Scan(&owner)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner != user) {
				return domain.ErrIdentityConflict
			}
		}
		if err != nil {
			return err
		}
		policy, err := settingspostgres.LockPublicPolicy(ctx, tx)
		if err != nil {
			return err
		}
		if err := policy.RequireMethod(settingsdomain.PrimaryMethod("oidc", key.Issuer), false); err != nil {
			return err
		}
		if err := settingspostgres.RequireProviderRevision(ctx, tx, key.Issuer, key.ProviderVersion); err != nil {
			return err
		}
		if !created {
			return nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.identity_audit(user_id,event,auth_version) VALUES ($1,'identity_linked',$2)`, user, version)
		return err
	})
}

func hasPermanentPassword(ctx context.Context, tx pgx.Tx, user domain.UserID) (bool, error) {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_credentials p
		JOIN auth.user_emails e ON e.id=p.email_id AND e.user_id=p.user_id
		WHERE p.user_id=$1 AND e.verified_at IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND activated_at IS NULL))`, user).Scan(&valid)
	return valid, err
}
