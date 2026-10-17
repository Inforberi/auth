package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
)

type refreshState struct {
	Family      domain.RefreshFamily
	UserID      accountdomain.UserID
	LedgerHash  string
	UsedAt      *time.Time
	Now         time.Time
	Active      bool
	Live        bool
	AuthVersion int64
}

func lockRefresh(ctx context.Context, tx pgx.Tx, verifier string) (refreshState, error) {
	var state refreshState
	var id string
	err := tx.QueryRow(ctx, `SELECT s.user_id,s.id FROM auth.refresh_tokens t JOIN auth.sessions s ON s.id=t.session_id WHERE t.token_hash=$1`, verifier).Scan(&state.UserID, &id)
	if err != nil {
		return state, refreshLookupError(err)
	}
	if err := tx.QueryRow(ctx, `SELECT auth_version,status='active' AND deleted_at IS NULL FROM auth.users WHERE id=$1 FOR SHARE`, state.UserID).Scan(&state.AuthVersion, &state.Active); err != nil {
		return state, refreshLookupError(err)
	}
	if err := tx.QueryRow(ctx, `SELECT token_hash,credential_profile='api' AND auth_version=$2 AND revoked_at IS NULL
		AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
		AND EXISTS(SELECT 1 FROM auth.role_bound_sessions b WHERE b.id=s.id)
		FROM auth.sessions s WHERE id=$1 AND credential_profile='api' FOR UPDATE OF s`, id, state.AuthVersion).Scan(&state.LedgerHash, &state.Live); err != nil {
		return state, refreshLookupError(err)
	}
	family := &state.Family
	err = tx.QueryRow(ctx, `SELECT f.session_id,f.audience,f.scope,f.idle_seconds,f.absolute_expires_at,f.last_rotated_at,f.generation,f.revoked_at,t.used_at,clock_timestamp()
		FROM auth.refresh_families f JOIN auth.refresh_tokens t ON t.session_id=f.session_id
		WHERE f.session_id=$1 AND t.token_hash=$2 FOR UPDATE OF f,t`, id, verifier).Scan(
		&family.SessionID, &family.Audience, &family.Scope, &family.IdleSeconds, &family.AbsoluteExpiresAt,
		&family.LastRotatedAt, &family.Generation, &family.RevokedAt, &state.UsedAt, &state.Now,
	)
	return state, refreshLookupError(err)
}

func refreshLookupError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrInvalidRefresh
	}
	return err
}
