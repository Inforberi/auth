package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func bindPlatformInitialEmail(ctx context.Context, tx pgx.Tx, c PlatformLifecycle) (domain.AuthVersion, domain.AddressID, error) {
	var version domain.AuthVersion
	err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='pending' AND deleted_at IS NULL FOR UPDATE`, c.UserID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", domain.ErrEmailBindingConflict
	}
	if err != nil {
		return 0, "", err
	}
	if version != c.ExpectedVersion {
		return 0, "", domain.ErrAccountConflict
	}
	var emailID domain.AddressID
	err = tx.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email)
		SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM auth.platform_user_creations WHERE user_id=$1 AND fingerprint='')
		AND NOT EXISTS(SELECT 1 FROM auth.user_emails WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.linked_identities WHERE user_id=$1)
		RETURNING id`, c.UserID, c.Email.String()).Scan(&emailID)
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_emails_email_key" {
		return 0, "", domain.ErrEmailBindingConflict
	}
	if err != nil {
		return 0, "", err
	}
	err = tx.QueryRow(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1 RETURNING auth_version`, c.UserID).Scan(&version)
	return version, emailID, err
}
