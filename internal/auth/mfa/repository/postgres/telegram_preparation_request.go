package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) IssueTelegramPreparation(ctx context.Context, proof service.Proof, input service.TelegramIntent) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := r.lockTelegramManagement(ctx, tx, proof, input.Bot)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.mfa_telegram_preparations
 (user_id,digest,session_id,session_hash,auth_version,bot_id,policy_version,expires_at)
 SELECT $1,$2,s.id,$3,$4,$5,$6,LEAST(clock_timestamp()+$7*interval '1 microsecond',$8)
 FROM auth.sessions s WHERE s.token_hash=$3
 ON CONFLICT(user_id) DO UPDATE SET digest=EXCLUDED.digest,session_id=EXCLUDED.session_id,session_hash=EXCLUDED.session_hash,
 auth_version=EXCLUDED.auth_version,bot_id=EXCLUDED.bot_id,policy_version=EXCLUDED.policy_version,
 telegram_user_id=NULL,update_id=NULL,verifier=NULL,payload=NULL,attempts=0,confirmed_at=NULL,
 created_at=clock_timestamp(),expires_at=EXCLUDED.expires_at RETURNING expires_at`,
			proof.UserID, input.Digest, proof.TokenHash, proof.AuthVersion, input.Bot.ID, input.Bot.PolicyVersion,
			input.TTL.Microseconds(), deadline).Scan(&expires)
		if err != nil {
			return err
		}
		if err := audit(ctx, tx, proof.UserID, "telegram_channel_requested"); err != nil {
			return err
		}
		return factorManagementDeadline(ctx, tx, expires)
	})
	return expires, telegramPreparationError(err)
}
