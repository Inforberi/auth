package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (r *Repository) CreateSession(ctx context.Context, p service.CreateSessionParams) (time.Time, error) {
	var expires time.Time
	verifiedAt := p.CreatedAt
	if p.PrimaryProof != nil {
		verifiedAt = p.PrimaryProof.VerifiedAt
	}
	administrative := p.PrimaryProof != nil && p.PrimaryProof.Administrative
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
			return err
		}
		var version int64
		var fresh bool
		if err := tx.QueryRow(ctx, `SELECT auth_version,$2::timestamptz<=clock_timestamp()+interval '5 seconds'
			AND $2>clock_timestamp()-interval '1 minute' FROM auth.users
			WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, p.UserID, verifiedAt).Scan(&version, &fresh); err != nil {
			return sessionError(err)
		}
		if p.AuthVersion <= 0 || version != p.AuthVersion {
			return domain.ErrSessionNotFound
		}
		method, issuer := "password", ""
		if p.PrimaryProof != nil {
			method, issuer = p.PrimaryProof.Method, p.PrimaryProof.Issuer
		}
		// A separate statement sees factor enrollment committed while waiting for the user lock.
		var mfaRequired bool
		if err := tx.QueryRow(ctx, `SELECT auth.mfa_login_required($1,$2)`, p.UserID, administrative).Scan(&mfaRequired); err != nil {
			return err
		}
		if mfaRequired {
			return domain.ErrMFARequired
		}
		if administrative {
			if !fresh || !mfaservice.ValidPrimary(*p.PrimaryProof) || p.PrimaryProof.UserID != p.UserID || p.PrimaryProof.AuthVersion != p.AuthVersion {
				return domain.ErrSessionNotFound
			}
			allowed, err := accesspostgres.AdministrativePasswordAllowed(ctx, tx, p.UserID, p.PrimaryProof.Reference)
			if err != nil {
				return err
			}
			if !allowed {
				return domain.ErrSessionNotFound
			}
		} else if err := settingspostgres.RequirePublicLogin(ctx, tx, p.UserID, method, issuer); err != nil {
			return err
		}
		if method == "oidc" {
			if err := settingspostgres.RequireProviderRevision(ctx, tx, issuer, p.PrimaryProof.ProviderVersion); err != nil {
				return err
			}
		}
		err := tx.QueryRow(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address,primary_method,primary_verified_at,
			idle_timeout_seconds,activity_interval_seconds,admin_absolute_seconds,password_verified_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,LEAST($10::timestamptz,statement_timestamp()),COALESCE(NULLIF($11,0),1800),COALESCE(NULLIF($12,0),60),COALESCE(NULLIF($13,0),43200),
			CASE WHEN $14::boolean THEN LEAST($10::timestamptz,statement_timestamp()) END) RETURNING expires_at`,
			p.TokenHash, p.UserID, version, p.CreatedAt, p.ExpiresAt, p.AbsoluteExpiresAt, p.UserAgent, p.IPAddress, method, verifiedAt,
			int64(p.AdminIdleTimeout/time.Second), int64(p.AdminActivityInterval/time.Second), int64(p.AdminAbsoluteTTL/time.Second), administrative).Scan(&expires)
		return err
	})
	return expires, err
}
