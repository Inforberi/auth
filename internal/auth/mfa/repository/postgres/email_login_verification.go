package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

const assistedRecoveryFactor domain.Method = "assisted_recovery"

func consumeLoginFactor(ctx context.Context, tx pgx.Tx, proof lockedLoginChallenge, factor service.LoginFactor, email *service.EmailCodeProof, telegram *service.TelegramCodeProof) (domain.Verification, error) {
	if proof.FactorMethod == domain.TelegramCode {
		if telegram == nil || email != nil || factor != nil || proof.Method != "password" || proof.Administrative {
			return domain.Verification{}, domain.ErrInvalidCode
		}
		return consumeTelegramLoginCode(ctx, tx, proof, *telegram)
	}
	if telegram != nil {
		return domain.Verification{}, domain.ErrInvalidCode
	}
	if proof.FactorMethod == domain.EmailCode {
		if email == nil || factor != nil || proof.Method != "password" || proof.Administrative {
			return domain.Verification{}, domain.ErrInvalidCode
		}
		return consumeEmailLoginCode(ctx, tx, proof, *email)
	}
	if proof.FactorMethod != domain.TOTP || factor == nil || email != nil {
		return domain.Verification{}, domain.ErrInvalidCode
	}
	check, recovery := factor(proof.UserID)
	return consumeFactor(ctx, tx, proof.UserID, check, recovery)
}

func consumeEmailLoginCode(ctx context.Context, tx pgx.Tx, proof lockedLoginChallenge, input service.EmailCodeProof) (domain.Verification, error) {
	var expected string
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT c.verifier,clock_timestamp() FROM auth.email_login_challenges c
 JOIN auth.mfa_email f ON f.user_id=c.user_id AND f.email_id=c.email_id
 JOIN auth.user_emails e ON e.user_id=c.user_id AND e.id=c.email_id CROSS JOIN auth.mfa_settings p
 WHERE c.digest=$1 AND c.mfa_digest=$2 AND c.user_id=$3 AND c.auth_version=$4 AND c.email_id=$5
 AND c.credential_profile=$6 AND c.purpose='mfa_email_login' AND c.session_hash IS NULL
 AND c.attempts<5 AND c.expires_at>clock_timestamp() AND p.singleton AND auth.email_factor_usable(c.user_id)
 AND NOT auth.has_administrative_access(c.user_id)
 AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=c.user_id)
 AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=c.user_id AND (activated_at IS NULL OR password_change_required))
 FOR UPDATE OF c FOR SHARE OF f,e,p`, input.Digest, proof.Digest, proof.UserID, proof.AuthVersion, proof.FactorEmailID, proof.Profile).Scan(&expected, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Verification{}, domain.ErrInvalidCode
	}
	if err != nil {
		return domain.Verification{}, err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(input.Verifier)) != 1 {
		if _, err := tx.Exec(ctx, `UPDATE auth.email_login_challenges SET attempts=attempts+1 WHERE digest=$1`, input.Digest); err != nil {
			return domain.Verification{}, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.email_login_outbox o USING auth.email_login_challenges c
 WHERE o.digest=c.digest AND c.digest=$1 AND c.attempts>=5`, input.Digest); err != nil {
			return domain.Verification{}, err
		}
		return domain.Verification{}, domain.ErrInvalidCode
	}
	return domain.Verification{Method: domain.EmailCode, VerifiedAt: now}, nil
}
