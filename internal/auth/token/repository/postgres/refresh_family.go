package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

// CreateRefreshFamily participates in final native login's transaction, after its Access/user/session guards.
// It neither authenticates a primary proof nor commits/returns a client credential on its own.
func CreateRefreshFamily(ctx context.Context, tx pgx.Tx, p service.CreateRefreshFamilyParams) (domain.RefreshFamily, error) {
	var family domain.RefreshFamily
	if err := p.Validate(); err != nil {
		return family, err
	}
	var user accountdomain.UserID
	err := tx.QueryRow(ctx, `SELECT s.user_id FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id
		WHERE s.id=$1 AND s.credential_profile='api' AND s.token_hash<>$2
		AND u.status='active' AND u.deleted_at IS NULL AND s.auth_version=u.auth_version
		AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
		AND s.primary_verified_at IS NOT NULL FOR UPDATE OF s`, p.SessionID, p.Verifier).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		return family, domain.ErrInvalidRefresh
	}
	if err != nil {
		return family, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO auth.refresh_families(session_id,audience,scope,idle_seconds,absolute_expires_at,created_at,last_rotated_at)
		SELECT id,$2,$3,LEAST($4::bigint,FLOOR(EXTRACT(EPOCH FROM expires_at-created_at))::bigint,
			FLOOR(EXTRACT(EPOCH FROM absolute_expires_at-statement_timestamp()))::bigint),
		absolute_expires_at,statement_timestamp(),statement_timestamp() FROM auth.sessions WHERE id=$1
		RETURNING session_id,audience,scope,idle_seconds,absolute_expires_at,last_rotated_at,generation,revoked_at`,
		p.SessionID, p.Audience, p.Scope, int64(p.IdleTTL/time.Second)).Scan(
		&family.SessionID, &family.Audience, &family.Scope, &family.IdleSeconds, &family.AbsoluteExpiresAt, &family.LastRotatedAt, &family.Generation, &family.RevokedAt,
	)
	if err != nil {
		return family, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.refresh_tokens(token_hash,session_id,generation,expires_at) VALUES ($1,$2,0,$3)`,
		p.Verifier, family.SessionID, family.AbsoluteExpiresAt); err != nil {
		return family, err
	}
	return family, auditRefresh(ctx, tx, user, family, "family_created")
}

func auditRefresh(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, family domain.RefreshFamily, event string) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth.refresh_audit(user_id,session_id,event,generation) VALUES ($1,$2,$3,$4)`,
		user, family.SessionID, event, family.Generation)
	return err
}
