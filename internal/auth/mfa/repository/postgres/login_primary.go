package postgres

import (
	"context"
	"errors"

	pgx "github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func RequireLoginPrimary(ctx context.Context, tx pgx.Tx, p mfaservice.PrimaryProof) error {
	return requireLoginPrimary(ctx, tx, p, false)
}

func RequireNativeLoginPrimary(ctx context.Context, tx pgx.Tx, p mfaservice.PrimaryProof) error {
	return requireLoginPrimary(ctx, tx, p, true)
}

func requireLoginPrimary(ctx context.Context, tx pgx.Tx, p mfaservice.PrimaryProof, native bool) error {
	var valid bool
	var err error
	if p.Administrative {
		if p.Method != "password" || native {
			return domain.ErrProofRequired
		}
		valid, err = accesspostgres.AdministrativePasswordAllowed(ctx, tx, p.UserID, p.Reference)
		if err != nil {
			return err
		}
		if !valid {
			return domain.ErrProofRequired
		}
		return nil
	}
	checkPolicy := settingspostgres.RequirePublicLogin
	if native {
		checkPolicy = settingspostgres.RequireNativeLogin
	}
	if err := checkPolicy(ctx, tx, p.UserID, p.Method, p.Issuer); err != nil {
		return err
	}
	if p.Method == "oidc" {
		if err := settingspostgres.RequireProviderRevision(ctx, tx, p.Issuer, p.ProviderVersion); err != nil {
			return err
		}
	}
	switch p.Method {
	case "password":
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_credentials
			WHERE user_id=$1 AND password_hash=$2)`, p.UserID, p.Reference).Scan(&valid)
	case "oidc":
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.linked_identities
			WHERE user_id=$1 AND issuer=$2 AND subject=$3)`, p.UserID, p.Issuer, p.Reference).Scan(&valid)
	case "emailotp":
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.user_emails e
			JOIN auth.password_credentials c ON c.user_id=e.user_id AND c.email_id=e.id
			WHERE e.user_id=$1 AND e.id=$2::uuid AND e.verified_at IS NOT NULL
			AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
			AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND activated_at IS NULL))`, p.UserID, p.Reference).Scan(&valid)
	}
	if err != nil {
		return err
	}
	if !valid {
		return domain.ErrProofRequired
	}
	return nil
}

func lockLoginPrimary(ctx context.Context, tx pgx.Tx, proof mfaservice.PrimaryProof) error {
	if proof.Administrative {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
	} else {
		if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
			return err
		}
	}
	var version int64
	var fresh bool
	// Bounded backend/DB clock skew must not turn into a future authentication time.
	err := tx.QueryRow(ctx, `SELECT auth_version,$2::timestamptz<=clock_timestamp()+interval '5 seconds'
			AND $2>clock_timestamp()-interval '1 minute' FROM auth.users
			WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR UPDATE`, proof.UserID, proof.VerifiedAt).Scan(&version, &fresh)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (version != proof.AuthVersion || !fresh)) {
		return domain.ErrProofRequired
	}
	if err != nil {
		return err
	}
	if err := RequireLoginPrimary(ctx, tx, proof); err != nil {
		return err
	}
	return nil
}
