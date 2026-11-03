package postgres

import (
	"context"
	"errors"
	"time"

	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type telegramPreparation struct {
	telegramID, updateID *int64
	verifier             *string
	payload              []byte
	expires              time.Time
}

func (r *Repository) lockTelegramManagement(ctx context.Context, tx pgx.Tx, proof mfaservice.Proof, bot domain.TelegramBotBinding) (time.Time, error) {
	deadline, err := r.lockPasswordFactorManagement(ctx, tx, proof)
	if err != nil {
		return time.Time{}, err
	}
	var version int64
	err = tx.QueryRow(ctx, `SELECT version FROM auth.mfa_settings
 WHERE singleton AND version=$1 AND telegram_bot_id=$2 FOR SHARE`, bot.PolicyVersion, bot.ID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, domain.ErrUnavailable
	}
	return deadline, err
}

func lockTelegramPreparation(ctx context.Context, tx pgx.Tx, proof mfaservice.Proof, bot domain.TelegramBotBinding, digest string) (telegramPreparation, error) {
	var pending telegramPreparation
	err := tx.QueryRow(ctx, `SELECT telegram_user_id,update_id,verifier,payload,expires_at
 FROM auth.mfa_telegram_preparations WHERE user_id=$1 AND digest=$2 AND session_hash=$3
 AND auth_version=$4 AND bot_id=$5 AND policy_version=$6 AND confirmed_at IS NULL
 AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE`, proof.UserID, digest, proof.TokenHash,
		proof.AuthVersion, bot.ID, bot.PolicyVersion).Scan(&pending.telegramID, &pending.updateID, &pending.verifier, &pending.payload, &pending.expires)
	return pending, telegramPreparationError(err)
}

func telegramPreparationError(err error) error {
	var database *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || errors.As(err, &database) && database.Code == "23505" {
		return domain.ErrInvalidTelegramPreparation
	}
	return err
}
