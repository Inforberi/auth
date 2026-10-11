package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func lockChangeAccount(ctx context.Context, tx pgx.Tx, user domain.UserID) (domain.AuthVersion, error) {
	var version domain.AuthVersion
	err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR UPDATE`, user).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.ErrInvalidEmailChange
	}
	return version, err
}

func invalidateChangeAccess(ctx context.Context, tx pgx.Tx, user domain.UserID) error {
	for _, query := range []string{
		`UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
		`UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`,
		`DELETE FROM auth.password_resets WHERE user_id=$1`,
		`DELETE FROM auth.email_verifications v USING auth.user_emails e WHERE v.email_id=e.id AND e.user_id=$1`,
		`UPDATE auth.email_changes SET state='cancelled' WHERE user_id=$1 AND state='pending'`,
		`DELETE FROM auth.email_change_outbox o USING auth.email_changes c WHERE o.change_id=c.id AND c.user_id=$1 AND o.kind='confirm'`,
	} {
		if _, err := tx.Exec(ctx, query, user); err != nil {
			return err
		}
	}
	return nil
}

func queueChangeMail(ctx context.Context, tx pgx.Tx, id, kind string, payload []byte, expiry time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth.email_change_outbox(change_id,kind,payload,expires_at) VALUES ($1,$2,$3,$4)`, id, kind, payload, expiry)
	return err
}

func auditEmailChange(ctx context.Context, tx pgx.Tx, user domain.UserID, id, event string) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth.email_change_audit(user_id,change_id,event) VALUES ($1,$2,$3)`, user, id, event)
	return err
}

func emailOwnershipError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_emails_email_key" {
		return domain.ErrInvalidEmailChange
	}
	return err
}
