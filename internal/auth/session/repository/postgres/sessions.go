package postgres

import (
	"context"
	"errors"
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
		// A separate statement sees factor enrollment committed while waiting for the user lock.
		var mfaRequired bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, p.UserID).Scan(&mfaRequired); err != nil {
			return err
		}
		if mfaRequired {
			return domain.ErrMFARequired
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
	err := r.db.QueryRow(ctx, `SELECT s.id,s.user_id,s.user_agent,s.ip_address,s.created_at,s.expires_at,s.absolute_expires_at,
		COALESCE(s.primary_method,''),s.primary_verified_at,s.mfa_verified_at
		FROM auth.sessions s JOIN auth.users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL
		AND s.auth_version=u.auth_version AND u.status='active' AND u.deleted_at IS NULL
		AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()`, token).
		Scan(&session.ID, &session.UserID, &session.UserAgent, &session.IPAddress, &session.CreatedAt, &session.ExpiresAt, &session.AbsoluteExpiresAt,
			&session.PrimaryMethod, &session.PrimaryVerifiedAt, &session.MFAVerifiedAt)
	if err != nil {
		return nil, sessionError(err)
	}
	return &session, nil
}

func (r *Repository) RefreshSession(ctx context.Context, token string, session *domain.Session, expectedExpiry time.Time) (bool, error) {
	extended := false
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, session.UserID).Scan(&version); err != nil {
			return sessionError(err)
		}
		var actual time.Time
		err := tx.QueryRow(ctx, `UPDATE auth.sessions SET expires_at=LEAST($2,absolute_expires_at)
			WHERE token_hash=$1 AND user_id=$3 AND auth_version=$4 AND revoked_at IS NULL
			AND expires_at=$5 AND expires_at<LEAST($2,absolute_expires_at)
			AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
			RETURNING expires_at`, token, session.ExpiresAt, session.UserID, version, expectedExpiry).Scan(&actual)
		if err == nil {
			session.ExpiresAt = actual
			extended = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// Another request may already have extended it. Never shorten or resurrect it.
		err = tx.QueryRow(ctx, `SELECT expires_at FROM auth.sessions
			WHERE token_hash=$1 AND user_id=$2 AND auth_version=$3 AND revoked_at IS NULL
			AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()`, token, session.UserID, version).Scan(&actual)
		if err != nil {
			return sessionError(err)
		}
		session.ExpiresAt = actual
		return nil
	})
	if err != nil {
		return false, err
	}
	return extended, nil
}
