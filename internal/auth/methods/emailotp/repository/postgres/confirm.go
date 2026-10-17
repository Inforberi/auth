package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (r *Repository) Consume(ctx context.Context, digest, verifier string) (*service.AuthenticatedAccount, error) {
	result, err := r.consume(ctx, digest, verifier, "browser")
	if err != nil {
		return nil, err
	}
	return &result.user, nil
}

func (r *Repository) ConsumeNative(ctx context.Context, digest, verifier string) (*service.NativeAuthentication, error) {
	result, err := r.consume(ctx, digest, verifier, "api")
	if err != nil {
		return nil, err
	}
	return &service.NativeAuthentication{Target: result.target, Proof: mfaservice.PrimaryProof{
		UserID: result.user.ID, AuthVersion: int64(result.user.AuthVersion), Method: "emailotp",
		Reference: string(result.user.EmailID), VerifiedAt: result.verifiedAt,
	}}, nil
}

type consumedLogin struct {
	user       service.AuthenticatedAccount
	target     mfaservice.NativeTarget
	verifiedAt time.Time
}

func (r *Repository) consume(ctx context.Context, digest, verifier, profile string) (*consumedLogin, error) {
	var result consumedLogin
	user := &result.user
	accepted := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT u.id,u.auth_version FROM auth.users u
   JOIN auth.email_login_challenges c ON c.user_id=u.id
   WHERE c.digest=$1 AND c.credential_profile=$2 AND c.purpose='login' FOR UPDATE OF u`, digest, profile).Scan(&user.ID, &user.AuthVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var expected string
		err = tx.QueryRow(ctx, `SELECT c.verifier,c.email_id,COALESCE(c.native_audience,''),c.native_scope,clock_timestamp() FROM auth.email_login_challenges c
   JOIN auth.user_emails e ON e.id=c.email_id AND e.user_id=c.user_id
   JOIN auth.password_credentials p ON p.user_id=c.user_id AND p.email_id=e.id
   JOIN auth.users u ON u.id=c.user_id
   WHERE c.digest=$1 AND c.purpose='login' AND c.credential_profile=$3 AND c.auth_version=$2 AND u.auth_version=$2 AND u.status='active' AND u.deleted_at IS NULL
   AND c.expires_at>clock_timestamp() AND c.attempts<5 AND e.verified_at IS NOT NULL
   AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials t WHERE t.user_id=u.id)
   AND NOT EXISTS(SELECT 1 FROM auth.account_provisions a WHERE a.user_id=u.id AND a.activated_at IS NULL)
   FOR UPDATE OF c`, digest, user.AuthVersion, profile).Scan(&expected, &user.EmailID, &result.target.Audience, &result.target.Scope, &result.verifiedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := settingspostgres.RequirePublicLogin(ctx, tx, user.ID, "emailotp", ""); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(verifier)) != 1 {
			return recordFailedCode(ctx, tx, digest)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.email_login_challenges WHERE digest=$1`, digest); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.email_login_audit(user_id,event,auth_version) VALUES ($1,'code_consumed',$2)`, user.ID, user.AuthVersion); err != nil {
			return err
		}
		accepted = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !accepted {
		return nil, domain.ErrInvalidCode
	}
	return &result, nil
}

func recordFailedCode(ctx context.Context, tx pgx.Tx, digest string) error {
	// Return the public error after commit, otherwise the attempt counter would roll back.
	if _, err := tx.Exec(ctx, `UPDATE auth.email_login_challenges SET attempts=attempts+1 WHERE digest=$1`, digest); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM auth.email_login_outbox WHERE digest=$1 AND EXISTS(
		SELECT 1 FROM auth.email_login_challenges WHERE digest=$1 AND attempts>=5)`, digest)
	return err
}
