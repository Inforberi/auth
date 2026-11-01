package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) EnableTelegramFactor(ctx context.Context, input service.FactorMutation, bot domain.TelegramBotBinding) error {
	proof := input.Proof
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := r.lockTelegramManagement(ctx, tx, proof, bot)
		if err != nil {
			return err
		}
		var allowed, eligible bool
		if err := tx.QueryRow(ctx, `SELECT telegram_factor_allowed,
 NOT auth.has_administrative_access($1) OR EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
 FROM auth.mfa_settings WHERE singleton`, proof.UserID).Scan(&allowed, &eligible); err != nil {
			return err
		}
		if !allowed || !eligible {
			return domain.ErrUnavailable
		}
		var telegramID int64
		var expires time.Time
		err = tx.QueryRow(ctx, `SELECT telegram_user_id,expires_at FROM auth.mfa_telegram_preparations
 WHERE user_id=$1 AND session_hash=$2 AND auth_version=$3 AND bot_id=$4 AND policy_version=$5
 AND confirmed_at<=clock_timestamp() AND expires_at>clock_timestamp() AND attempts<5
 AND telegram_user_id IS NOT NULL FOR UPDATE`, proof.UserID, proof.TokenHash, proof.AuthVersion, bot.ID, bot.PolicyVersion).Scan(&telegramID, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidTelegramPreparation
		}
		if err != nil {
			return err
		}
		if expires.Before(deadline) {
			deadline = expires
		}
		var configured bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=$1)`, proof.UserID).Scan(&configured); err != nil {
			return err
		}
		changed, err := tx.Exec(ctx, `INSERT INTO auth.mfa_telegram(user_id,bot_id,telegram_user_id) VALUES($1,$2,$3)
 ON CONFLICT(user_id) DO UPDATE SET bot_id=EXCLUDED.bot_id,telegram_user_id=EXCLUDED.telegram_user_id,enabled_at=clock_timestamp()
 WHERE (auth.mfa_telegram.bot_id,auth.mfa_telegram.telegram_user_id) IS DISTINCT FROM (EXCLUDED.bot_id,EXCLUDED.telegram_user_id)`, proof.UserID, bot.ID, telegramID)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return domain.ErrConflict
		}
		if err := invalidateFactors(ctx, tx, proof.UserID); err != nil {
			return err
		}
		event := "telegram_factor_enabled"
		if configured {
			event = "telegram_factor_replaced"
		}
		if err := telegramFactorNotice(ctx, tx, input, event); err != nil {
			return err
		}
		return factorManagementDeadline(ctx, tx, deadline)
	})
	var database *pgconn.PgError
	if errors.As(err, &database) && database.Code == "23505" {
		return domain.ErrConflict
	}
	return err
}
