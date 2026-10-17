package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func authorizeCaller(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, hash string, write bool) (int64, error) {
	lock := "FOR SHARE"
	if write {
		lock = "FOR UPDATE"
	}
	var version int64
	if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL `+lock, user).Scan(&version); err != nil {
		return 0, sessionError(err)
	}
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions WHERE user_id=$1 AND token_hash=$2 AND credential_profile='browser'
  AND auth_version=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp())`, user, hash, version).Scan(&valid)
	if err != nil {
		return 0, err
	}
	if !valid {
		return 0, domain.ErrSessionNotFound
	}
	return version, nil
}

func (r *Repository) ListOwnSessions(ctx context.Context, user accountdomain.UserID, hash, before string, limit int) ([]domain.Session, error) {
	sessions := make([]domain.Session, 0)
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		version, err := authorizeCaller(ctx, tx, user, hash, false)
		if err != nil {
			return err
		}
		var cursorTime any
		if before != "" {
			var created time.Time
			err := tx.QueryRow(ctx, `SELECT created_at FROM auth.role_bound_sessions WHERE id=$1 AND user_id=$2`, before, user).Scan(&created)
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrInvalidSessionID
			}
			if err != nil {
				return err
			}
			cursorTime = created
		}
		rows, err := tx.Query(ctx, `SELECT id,user_agent,ip_address,created_at,expires_at,absolute_expires_at
   FROM auth.role_bound_sessions WHERE user_id=$1 AND auth_version=$2 AND revoked_at IS NULL
   AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
   AND ($3::timestamptz IS NULL OR (created_at,id)<($3::timestamptz,$4::uuid))
   ORDER BY created_at DESC,id DESC LIMIT $5`, user, version, cursorTime, nullableCursor(before), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var session domain.Session
			session.UserID = user
			if err := rows.Scan(&session.ID, &session.UserAgent, &session.IPAddress, &session.CreatedAt, &session.ExpiresAt, &session.AbsoluteExpiresAt); err != nil {
				return err
			}
			sessions = append(sessions, session)
		}
		return rows.Err()
	})
	return sessions, err
}

func nullableCursor(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func (r *Repository) RevokeOwnSession(ctx context.Context, user accountdomain.UserID, hash, id string) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		version, err := authorizeCaller(ctx, tx, user, hash, true)
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `UPDATE auth.role_bound_sessions SET revoked_at=clock_timestamp()
   WHERE id=$1 AND user_id=$2 AND auth_version=$3 AND revoked_at IS NULL
   AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()`, id, user, version)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return domain.ErrOwnedSessionNotFound
		}
		return auditSessionRevocation(ctx, tx, user)
	})
}

func (r *Repository) RevokeOwnSessions(ctx context.Context, user accountdomain.UserID, hash string) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := authorizeCaller(ctx, tx, user, hash, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, user); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, user); err != nil {
			return err
		}
		return auditSessionRevocation(ctx, tx, user)
	})
}

func auditSessionRevocation(ctx context.Context, tx pgx.Tx, user accountdomain.UserID) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event) VALUES ($1,'sessions_revoked')`, user)
	return err
}
