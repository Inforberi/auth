package postgres

import (
	"context"
	"crypto/subtle"

	pgx "github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
)

func (r *Repository) ConfirmTelegramPreparation(ctx context.Context, proof mfaservice.Proof, input mfatelegram.TelegramConfirmation) (*mfatelegram.TelegramPrepared, error) {
	var result mfatelegram.TelegramPrepared
	rejected := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := r.lockTelegramManagement(ctx, tx, proof, input.Bot)
		if err != nil {
			return err
		}
		pending, err := lockTelegramPreparation(ctx, tx, proof, input.Bot, input.Digest)
		if err != nil {
			return err
		}
		if pending.telegramID == nil || pending.verifier == nil {
			return domain.ErrInvalidTelegramPreparation
		}
		if pending.expires.Before(deadline) {
			deadline = pending.expires
		}
		if subtle.ConstantTimeCompare([]byte(*pending.verifier), []byte(input.Verifier)) != 1 {
			rejected = true
			if _, err := tx.Exec(ctx, `UPDATE auth.mfa_telegram_preparations SET attempts=attempts+1 WHERE user_id=$1`, proof.UserID); err != nil {
				return err
			}
			return factorManagementDeadline(ctx, tx, deadline)
		}
		changed, err := tx.Exec(ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE token_hash=$1`, proof.TokenHash, input.SessionHash)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return domain.ErrProofRequired
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.mfa_telegram_preparations SET session_hash=$2,confirmed_at=clock_timestamp(),verifier=NULL,payload=NULL
 WHERE user_id=$1`, proof.UserID, input.SessionHash); err != nil {
			return err
		}
		if err := audit(ctx, tx, proof.UserID, "telegram_channel_confirmed"); err != nil {
			return err
		}
		result.BotID, result.TelegramID, result.ExpiresAt = input.Bot.ID, *pending.telegramID, pending.expires
		return factorManagementDeadline(ctx, tx, deadline)
	})
	if err != nil {
		return nil, telegramPreparationError(err)
	}
	if rejected {
		return nil, domain.ErrInvalidTelegramPreparation
	}
	return &result, nil
}
