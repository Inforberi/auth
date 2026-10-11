package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) UnlinkIdentity(ctx context.Context, user domain.UserID, token, issuer string, freshFor time.Duration) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		version, err := lockIdentitySession(ctx, tx, user, token, freshFor)
		if err != nil {
			return err
		}
		var linked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.linked_identities WHERE user_id=$1 AND issuer=$2)`, user, issuer).Scan(&linked); err != nil {
			return err
		}
		if !linked {
			return domain.ErrIdentityNotFound
		}
		password, err := hasPermanentPassword(ctx, tx, user)
		if err != nil {
			return err
		}
		// Telegram is the only external method currently enabled; email alone is not a login method.
		if !password {
			return domain.ErrLastLoginMethod
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.linked_identities WHERE user_id=$1 AND issuer=$2`, user, issuer); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, user); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, user); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.identity_audit(user_id,event,auth_version) VALUES ($1,'identity_unlinked',$2)`, user, version+1)
		return err
	})
}
