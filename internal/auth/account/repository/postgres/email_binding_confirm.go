package postgres

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) ConfirmEmailBinding(ctx context.Context, proof mfaservice.Proof, verifier string) error {
	rejected := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var actor accessservice.Principal
		err := tx.QueryRow(ctx, `SELECT actor_id,actor_session_hash FROM auth.email_bindings
			WHERE user_id=$1 AND auth_version=$2 AND expires_at>clock_timestamp() AND attempts<5`, proof.UserID, proof.AuthVersion).Scan(&actor.UserID, &actor.TokenHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidEmailBinding
		}
		if err != nil {
			return err
		}
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, actor, string(proof.UserID), accesssettings.EmailBindingManage); err != nil {
			if errors.Is(err, accessdomain.ErrForbidden) || errors.Is(err, accessdomain.ErrFreshAuthRequired) {
				return domain.ErrInvalidEmailBinding
			}
			return err
		}
		version, err := requireInitialEmailTarget(ctx, tx, proof.UserID)
		if err != nil {
			return err
		}
		if int64(version) != proof.AuthVersion {
			return domain.ErrInvalidEmailBinding
		}
		if err := requireBindingSession(ctx, tx, proof.UserID, proof.TokenHash, version); err != nil {
			return err
		}
		var email, expected string
		err = tx.QueryRow(ctx, `SELECT email,verifier FROM auth.email_bindings
			WHERE user_id=$1 AND actor_id=$2 AND actor_session_hash=$3 AND auth_version=$4
			AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE`, proof.UserID, actor.UserID, actor.TokenHash, version).Scan(&email, &expected)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidEmailBinding
		}
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(verifier)) != 1 {
			rejected = true
			_, err := tx.Exec(ctx, `UPDATE auth.email_bindings SET attempts=attempts+1 WHERE user_id=$1`, proof.UserID)
			return err
		}
		return commitEmailBinding(ctx, tx, proof.UserID, actor.UserID, email)
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_emails_email_key" {
		return domain.ErrEmailBindingConflict
	}
	if err != nil {
		return err
	}
	if rejected {
		return domain.ErrInvalidEmailBinding
	}
	return nil
}

func commitEmailBinding(ctx context.Context, tx pgx.Tx, user, actor domain.UserID, email string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES ($1,$2,clock_timestamp())`, user, email); err != nil {
		return err
	}
	var version domain.AuthVersion
	if err := tx.QueryRow(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1 RETURNING auth_version`, user).Scan(&version); err != nil {
		return err
	}
	for _, query := range []string{
		`UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`,
		`DELETE FROM auth.email_bindings WHERE user_id=$1`,
		`DELETE FROM auth.mfa_enrollments WHERE user_id=$1`,
		`DELETE FROM auth.mfa_login_challenges WHERE user_id=$1`,
		`DELETE FROM auth.email_login_challenges WHERE user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, query, user); err != nil {
			return err
		}
	}
	return auditEmailBinding(ctx, tx, user, actor, version, "email_bound")
}
