package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	pgx "github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) TelegramLoginChannel(ctx context.Context, proof mfaservice.PrimaryProof) (mfalogin.TelegramLoginChannel, error) {
	var channel mfalogin.TelegramLoginChannel
	err := r.db.QueryRow(ctx, `SELECT f.bot_id,f.telegram_user_id,p.version
 FROM auth.mfa_telegram f JOIN auth.users u ON u.id=f.user_id
 JOIN auth.password_credentials c ON c.user_id=u.id CROSS JOIN auth.mfa_settings p
 WHERE u.id=$1 AND u.auth_version=$2 AND c.password_hash=$3 AND p.singleton
 AND auth.telegram_factor_usable(u.id) AND NOT auth.has_administrative_access(u.id)`,
		proof.UserID, proof.AuthVersion, proof.Reference).Scan(&channel.Bot.ID, &channel.TelegramID, &channel.Bot.PolicyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return channel, domain.ErrProofRequired
	}
	return channel, err
}

func lockTelegramLoginChannel(ctx context.Context, tx pgx.Tx, proof mfaservice.PrimaryProof, channel mfalogin.TelegramLoginChannel) error {
	if proof.Method != "password" || proof.Administrative {
		return domain.ErrProofRequired
	}
	var current bool
	err := tx.QueryRow(ctx, `SELECT true FROM auth.mfa_telegram f CROSS JOIN auth.mfa_settings p
 WHERE f.user_id=$1 AND f.bot_id=$2 AND f.telegram_user_id=$3 AND p.singleton AND p.version=$4
 AND auth.telegram_factor_usable(f.user_id) AND NOT auth.has_administrative_access(f.user_id)
 FOR SHARE OF f,p`, proof.UserID, channel.Bot.ID, channel.TelegramID, channel.Bot.PolicyVersion).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrProofRequired
	}
	return err
}

func (r *Repository) SaveTelegramLoginChallenge(ctx context.Context, input mfalogin.TelegramLoginIntent, ttl time.Duration) (*mfalogin.LoginChallengeState, error) {
	return r.saveLoginChallenge(ctx, input.Proof, input.Target, input.Digest, input.BindingHash, ttl, nil, &input)
}

func (r *Repository) MarkTelegramLoginDelivered(ctx context.Context, input mfalogin.TelegramLoginIntent) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		profile := "browser"
		if input.Target != nil {
			profile = "api"
		}
		proof, err := lockLoginChallengeProfile(ctx, tx, input.Digest, input.BindingHash, false, profile)
		if err != nil {
			return err
		}
		if proof.UserID != input.Proof.UserID || proof.AuthVersion != input.Proof.AuthVersion || proof.FactorMethod != domain.TelegramCode {
			return domain.ErrInvalidCode
		}
		checkPrimary := RequireLoginPrimary
		if profile == "api" {
			checkPrimary = RequireNativeLoginPrimary
		}
		if err := checkPrimary(ctx, tx, proof.PrimaryProof); err != nil {
			return err
		}
		if err := lockTelegramLoginChannel(ctx, tx, proof.PrimaryProof, input.Channel); err != nil {
			return err
		}
		changed, err := tx.Exec(ctx, `UPDATE auth.mfa_telegram_login_codes SET delivered_at=clock_timestamp()
 WHERE digest=$1 AND bot_id=$2 AND telegram_user_id=$3 AND policy_version=$4 AND verifier=$5 AND delivered_at IS NULL`,
			input.Digest, input.Channel.Bot.ID, input.Channel.TelegramID, input.Channel.Bot.PolicyVersion, input.Verifier)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return domain.ErrInvalidCode
		}
		return requireLoginDeadline(ctx, tx, proof.ExpiresAt)
	})
}

func consumeTelegramLoginCode(ctx context.Context, tx pgx.Tx, proof lockedLoginChallenge, input mfalogin.TelegramCodeProof) (domain.Verification, error) {
	var expected string
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT c.verifier,clock_timestamp() FROM auth.mfa_telegram_login_codes c
 JOIN auth.mfa_telegram f ON f.user_id=$2 AND f.bot_id=c.bot_id AND f.telegram_user_id=c.telegram_user_id
 CROSS JOIN auth.mfa_settings p WHERE c.digest=$1 AND c.delivered_at<=clock_timestamp()
 AND p.singleton AND p.version=c.policy_version AND auth.telegram_factor_usable(f.user_id)
 AND NOT auth.has_administrative_access(f.user_id) FOR UPDATE OF c FOR SHARE OF f,p`, proof.Digest, proof.UserID).Scan(&expected, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Verification{}, domain.ErrInvalidCode
	}
	if err != nil {
		return domain.Verification{}, err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(input.Verifier)) != 1 {
		return domain.Verification{}, domain.ErrInvalidCode
	}
	return domain.Verification{Method: domain.TelegramCode, VerifiedAt: now}, nil
}
