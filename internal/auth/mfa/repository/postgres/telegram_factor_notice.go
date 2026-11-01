package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func telegramFactorNotice(ctx context.Context, tx pgx.Tx, input service.FactorMutation, event string) error {
	if input.PrepareNotice == nil {
		return domain.ErrUnavailable
	}
	var email string
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT email::text,clock_timestamp() FROM auth.user_emails
 WHERE user_id=$1 AND verified_at<=clock_timestamp() ORDER BY verified_at,id LIMIT 1 FOR SHARE`, input.UserID).Scan(&email, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return audit(ctx, tx, input.UserID, event)
	}
	if err != nil {
		return err
	}
	payload, err := input.PrepareNotice(email, event, now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_security_outbox(user_id,notice_kind,payload) VALUES($1,$2,$3)`, input.UserID, event, payload); err != nil {
		return err
	}
	return audit(ctx, tx, input.UserID, event)
}
