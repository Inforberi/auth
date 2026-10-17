package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
)

func auditIssuance(ctx context.Context, tx pgx.Tx, input service.ExchangeInput, mode string, token *signing.SignedToken) error {
	// SQL time closes the gap between the locked snapshot, local signing and commit.
	tag, err := tx.Exec(ctx, `INSERT INTO auth.token_issuance_audit(user_id,session_id,token_id,audience,scope,validation_mode,expires_at)
		SELECT $1,$2,$3,$4,$5,$6,$7 WHERE $7::timestamptz>clock_timestamp()
		AND EXISTS(SELECT 1 FROM auth.role_bound_sessions WHERE id=$2 AND revoked_at IS NULL
		AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp())`,
		input.Actor.UserID, input.SessionID, token.ID, input.Audience, input.Scope, mode, token.ExpiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return sessiondomain.ErrSessionExpired
	}
	return nil
}
