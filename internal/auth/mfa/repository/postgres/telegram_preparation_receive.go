package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) ReceiveTelegramPreparation(ctx context.Context, input service.TelegramCandidate) (*service.TelegramEnvelope, error) {
	var result service.TelegramEnvelope
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var proof service.Proof
		if err := tx.QueryRow(ctx, `SELECT user_id,session_hash,auth_version FROM auth.mfa_telegram_preparations
 WHERE digest=$1 AND bot_id=$2 AND policy_version=$3 AND confirmed_at IS NULL`, input.Digest,
			input.Bot.ID, input.Bot.PolicyVersion).Scan(&proof.UserID, &proof.TokenHash, &proof.AuthVersion); err != nil {
			return err
		}
		deadline, err := r.lockTelegramManagement(ctx, tx, proof, input.Bot)
		if err != nil {
			return err
		}
		pending, err := lockTelegramPreparation(ctx, tx, proof, input.Bot, input.Digest)
		if err != nil {
			return err
		}
		if pending.expires.Before(deadline) {
			deadline = pending.expires
		}
		result.TelegramID, result.ExpiresAt = input.TelegramID, pending.expires
		if pending.telegramID != nil {
			if *pending.telegramID != input.TelegramID || *pending.updateID != input.UpdateID {
				return domain.ErrInvalidTelegramPreparation
			}
			result.Payload = pending.payload
			return factorManagementDeadline(ctx, tx, deadline)
		}
		// Reclaim only an expired short-lived preparation, never an enrolled factor.
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_telegram_preparations
 WHERE bot_id=$1 AND telegram_user_id=$2 AND expires_at<=clock_timestamp()`, input.Bot.ID, input.TelegramID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.mfa_telegram_preparations SET telegram_user_id=$2,update_id=$3,
 verifier=$4,payload=$5 WHERE user_id=$1`, proof.UserID, input.TelegramID, input.UpdateID, input.Verifier, input.Payload); err != nil {
			return err
		}
		result.Payload = input.Payload
		if err := audit(ctx, tx, proof.UserID, "telegram_channel_received"); err != nil {
			return err
		}
		return factorManagementDeadline(ctx, tx, deadline)
	})
	if err != nil {
		return nil, telegramPreparationError(err)
	}
	return &result, nil
}
