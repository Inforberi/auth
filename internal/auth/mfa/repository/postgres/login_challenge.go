package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (r *Repository) SaveLoginChallenge(ctx context.Context, proof service.PrimaryProof, digest, binding string, ttl time.Duration) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if proof.Administrative {
			if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
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
		if err := requireLoginPrimary(ctx, tx, proof); err != nil {
			return err
		}
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, proof.UserID).Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			return domain.ErrConflict
		}
		// A new primary challenge never inherits approval for an older candidate/browser.
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_requests WHERE user_id=$1`, proof.UserID); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.mfa_login_challenges
			(user_id,digest,binding_hash,auth_version,primary_method,primary_reference,primary_issuer,primary_verified_at,expires_at,administrative)
			VALUES ($1,$2,$3,$4,$5,$6,$7,LEAST($8::timestamptz,statement_timestamp()),statement_timestamp()+$9::double precision*interval '1 second',$10)
			ON CONFLICT(user_id) DO UPDATE SET digest=EXCLUDED.digest,binding_hash=EXCLUDED.binding_hash,
			auth_version=EXCLUDED.auth_version,primary_method=EXCLUDED.primary_method,primary_reference=EXCLUDED.primary_reference,
			primary_issuer=EXCLUDED.primary_issuer,primary_verified_at=EXCLUDED.primary_verified_at,administrative=EXCLUDED.administrative,attempts=0,
			created_at=statement_timestamp(),expires_at=EXCLUDED.expires_at RETURNING expires_at`,
			proof.UserID, digest, binding, proof.AuthVersion, proof.Method, proof.Reference, proof.Issuer, proof.VerifiedAt, ttl.Seconds(), proof.Administrative).Scan(&expires)
		if err != nil {
			return err
		}
		return audit(ctx, tx, proof.UserID, "login_challenge_started")
	})
	return expires, err
}

func requireLoginPrimary(ctx context.Context, tx pgx.Tx, p service.PrimaryProof) error {
	var valid bool
	var err error
	if p.Administrative {
		if p.Method != "password" {
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
	if err := settingspostgres.RequirePublicLogin(ctx, tx, p.UserID, p.Method, p.Issuer); err != nil {
		return err
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

func (r *Repository) FindLoginOwner(ctx context.Context, digest, binding string) (accountdomain.UserID, error) {
	var user accountdomain.UserID
	err := r.db.QueryRow(ctx, `SELECT c.user_id FROM auth.mfa_login_challenges c JOIN auth.users u ON u.id=c.user_id
		WHERE c.digest=$1 AND c.binding_hash=$2 AND c.auth_version=u.auth_version AND c.attempts<5
		AND c.expires_at>clock_timestamp() AND u.status='active' AND u.deleted_at IS NULL`, digest, binding).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrInvalidCode
	}
	return user, err
}
