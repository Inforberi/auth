package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) DeleteAccount(ctx context.Context, deletion domain.AccountDeletion) (domain.AuthVersion, error) {
	var version domain.AuthVersion
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		var err error
		version, err = deleteAccount(ctx, tx, deletion)
		return err
	})
	if err != nil {
		return 0, err
	}
	return version, err
}

func (r *Repository) DeleteUserAccount(ctx context.Context, actor accessservice.Principal, deletion domain.AccountDeletion) (domain.AuthVersion, error) {
	var version domain.AuthVersion
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, actor, string(deletion.UserID), settings.UsersDelete); err != nil {
			return err
		}
		deletion.ActorID = actor.UserID
		var err error
		version, err = deleteAccount(ctx, tx, deletion)
		return err
	})
	if err != nil {
		return 0, err
	}
	return version, err
}

func deleteAccount(ctx context.Context, tx pgx.Tx, deletion domain.AccountDeletion) (domain.AuthVersion, error) {
	var version domain.AuthVersion
	var deleted *time.Time
	err := tx.QueryRow(ctx, `SELECT auth_version,deleted_at FROM auth.users WHERE id=$1 FOR UPDATE`, deletion.UserID).Scan(&version, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.ErrAccountNotFound
	}
	if err != nil {
		return 0, err
	}
	if version != deletion.ExpectedVersion {
		return 0, domain.ErrAccountConflict
	}
	// Retry with the current version is a no-op, never a restoration.
	if deleted != nil {
		return version, nil
	}
	if err := accesspostgres.RequireAdministratorRemains(ctx, tx, deletion.UserID); err != nil {
		return 0, err
	}
	if err := tx.QueryRow(ctx, `UPDATE auth.users SET email_reuse_blocked=(status='blocked'),status='blocked',deleted_at=clock_timestamp(),
			auth_version=auth_version+1 WHERE id=$1 RETURNING auth_version`, deletion.UserID).Scan(&version); err != nil {
		return 0, err
	}
	for _, query := range []string{
		`UPDATE auth.sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()),user_agent='',ip_address='' WHERE user_id=$1`,
		`DELETE FROM auth.password_credentials WHERE user_id=$1`,
		`DELETE FROM auth.email_bindings WHERE user_id=$1`,
		`DELETE FROM auth.mfa_enrollments WHERE user_id=$1`,
		`DELETE FROM auth.mfa_login_challenges WHERE user_id=$1`,
		`DELETE FROM auth.mfa_totp WHERE user_id=$1`,
		`DELETE FROM auth.temporary_password_credentials WHERE user_id=$1`,
		`DELETE FROM auth.account_invitations WHERE user_id=$1`,
		`DELETE FROM auth.email_verifications v USING auth.user_emails e WHERE v.email_id=e.id AND e.user_id=$1`,
		`DELETE FROM auth.email_changes WHERE user_id=$1`,
		`DELETE FROM auth.user_profile WHERE user_id=$1`,
		`UPDATE auth.user_emails SET verified_at=NULL,verification_sent_at=NULL WHERE user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, query, deletion.UserID); err != nil {
			return 0, err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.account_deletion_audit(user_id,actor_id,auth_version)
			VALUES ($1,$2,$3)`, deletion.UserID, deletion.ActorID, version)
	if err != nil {
		return 0, err
	}
	return version, nil
}
