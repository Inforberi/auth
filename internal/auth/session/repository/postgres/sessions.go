package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func (r *Repository) CreateSession(ctx context.Context, p service.CreateSessionParams) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, p.UserID).Scan(&version); err != nil {
			return sessionError(err)
		}
		if p.AuthVersion <= 0 || version != p.AuthVersion {
			return domain.ErrSessionNotFound
		}
		_, err := tx.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, p.TokenHash, p.UserID, version, p.CreatedAt, p.ExpiresAt, p.AbsoluteExpiresAt, p.UserAgent, p.IPAddress)
		return err
	})
}

func (r *Repository) FindSession(ctx context.Context, token string) (*domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var session domain.Session
	err := r.db.QueryRow(ctx, `SELECT s.id,s.user_id,s.user_agent,s.ip_address,s.created_at,s.expires_at,s.absolute_expires_at
		FROM auth.sessions s JOIN auth.users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL
		AND s.auth_version=u.auth_version AND u.status='active' AND u.deleted_at IS NULL
		AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()`, token).
		Scan(&session.ID, &session.UserID, &session.UserAgent, &session.IPAddress, &session.CreatedAt, &session.ExpiresAt, &session.AbsoluteExpiresAt)
	if err != nil {
		return nil, sessionError(err)
	}
	return &session, nil
}

func (r *Repository) UpdateSession(ctx context.Context, token string, session *domain.Session, _ time.Duration) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, session.UserID).Scan(&version); err != nil {
			return sessionError(err)
		}
		result, err := tx.Exec(ctx, `UPDATE auth.sessions SET expires_at=LEAST($2,absolute_expires_at)
			WHERE token_hash=$1 AND user_id=$3 AND auth_version=$4 AND revoked_at IS NULL
			AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()`, token, session.ExpiresAt, session.UserID, version)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return domain.ErrSessionNotFound
		}
		return nil
	})
}
