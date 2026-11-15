package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func enqueueInvitation(ctx context.Context, tx pgx.Tx, user domain.UserID, email domain.AddressID, invitation domain.Invitation, ttl time.Duration) error {
	_, err := tx.Exec(ctx, `WITH issued AS (
		INSERT INTO auth.account_invitations(digest,user_id,email_id,auth_version,expires_at)
		VALUES($1,$2,$3,1,clock_timestamp()+$4::double precision*interval '1 second')
		RETURNING digest,expires_at
	)
	INSERT INTO auth.invitation_outbox(digest,payload,expires_at)
	SELECT digest,$5,expires_at FROM issued`, invitation.Digest, user, email, ttl.Seconds(), invitation.Payload)
	return err
}
