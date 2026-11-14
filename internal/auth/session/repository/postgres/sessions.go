package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func (r *Repository) FindSession(ctx context.Context, token string) (*domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var session domain.Session
	const selectSession = `SELECT s.id,s.user_id,s.user_agent,s.ip_address,s.created_at,s.expires_at,s.absolute_expires_at,
		COALESCE(s.primary_method,''),s.primary_verified_at,s.mfa_verified_at,COALESCE(s.mfa_method,''),s.auth_version,s.idle_timeout_seconds`
	const whereSession = ` JOIN auth.users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL
		AND s.credential_profile='browser' AND s.auth_version=u.auth_version AND u.status='active' AND u.deleted_at IS NULL
		AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()`
	query := selectSession + ` FROM auth.role_bound_sessions s` + whereSession
	dest := []any{
		&session.ID, &session.UserID, &session.UserAgent, &session.IPAddress, &session.CreatedAt, &session.ExpiresAt, &session.AbsoluteExpiresAt,
		&session.PrimaryMethod, &session.PrimaryVerifiedAt, &session.MFAVerifiedAt, &session.MFAMethod, &session.AuthVersion, &session.IdleTimeoutSeconds,
	}
	if r.browserPolicy {
		query = selectSession + `,COALESCE(lifetime.browser_idle_seconds,0),COALESCE(lifetime.browser_refresh_seconds,0)
			FROM auth.role_bound_sessions s JOIN auth.sessions lifetime ON lifetime.token_hash=s.token_hash` + whereSession
		dest = append(dest, &session.BrowserIdleSeconds, &session.BrowserRefreshSeconds)
	}
	err := r.db.QueryRow(ctx, query, token).Scan(dest...)
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
		err := tx.QueryRow(ctx, `UPDATE auth.role_bound_sessions SET expires_at=LEAST($2,absolute_expires_at)
			WHERE token_hash=$1 AND user_id=$3 AND auth_version=$4 AND revoked_at IS NULL
			AND credential_profile='browser'
			AND idle_timeout_seconds=0
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
		err = tx.QueryRow(ctx, `SELECT expires_at FROM auth.role_bound_sessions
			WHERE token_hash=$1 AND user_id=$2 AND auth_version=$3 AND revoked_at IS NULL
			AND credential_profile='browser'
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
