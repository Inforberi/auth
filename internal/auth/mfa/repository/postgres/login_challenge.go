package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) SaveLoginChallenge(ctx context.Context, proof service.PrimaryProof, digest, binding string, ttl time.Duration) (*service.LoginChallengeState, error) {
	return r.saveLoginChallenge(ctx, proof, nil, digest, binding, ttl, nil, nil)
}

func (r *Repository) SaveNativeLoginChallenge(ctx context.Context, proof service.PrimaryProof, target service.NativeTarget, digest, binding string, ttl time.Duration) (*service.LoginChallengeState, error) {
	return r.saveLoginChallenge(ctx, proof, &target, digest, binding, ttl, nil, nil)
}

func (r *Repository) saveLoginChallenge(ctx context.Context, proof service.PrimaryProof, target *service.NativeTarget, digest, binding string, ttl time.Duration, mail *otpservice.EmailLoginIntent, telegramIntent *service.TelegramLoginIntent) (*service.LoginChallengeState, error) {
	profile := "browser"
	var bound service.NativeTarget
	var audience *string
	if target != nil {
		profile = "api"
		bound = *target
		audience = &bound.Audience
	}
	var result service.LoginChallengeState
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := lockLoginPrimary(ctx, tx, proof); err != nil {
			return err
		}
		var enabled, required, email, telegram bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1),auth.mfa_required($1,$2),EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1),EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=$1)`, proof.UserID, proof.Administrative).Scan(&enabled, &required, &email, &telegram); err != nil {
			return err
		}
		factor := domain.TOTP
		var emailID *string
		var emailExpiry *time.Time
		switch {
		case telegramIntent != nil:
			if err := lockTelegramLoginChannel(ctx, tx, proof, telegramIntent.Channel); err != nil {
				return err
			}
			factor, enabled = domain.TelegramCode, true
		case mail != nil:
			id, err := lockEmailLoginChannel(ctx, tx, proof, mail.Channel)
			if err != nil {
				return err
			}
			factor, emailID, emailExpiry, enabled = domain.EmailCode, &id, &mail.Code.ExpiresAt, true
		case (email || telegram) && !enabled:
			if proof.Method != "password" || proof.Administrative {
				return domain.ErrProofRequired
			}
			factor, enabled = assistedRecoveryFactor, true
			result.RecoveryRequired = true
		}
		if !enabled && !required {
			return domain.ErrConflict
		}
		result.EnrollmentRequired = !enabled
		result.Method = factor

		// A new primary challenge never inherits approval for an older candidate/browser.
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_requests WHERE user_id=$1`, proof.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `WITH discarded AS(DELETE FROM auth.mfa_telegram_login_codes WHERE digest IN(SELECT digest FROM auth.mfa_login_challenges WHERE user_id=$1)) DELETE FROM auth.email_login_challenges WHERE user_id=$1 AND purpose='mfa_email_login'`, proof.UserID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `INSERT INTO auth.mfa_login_challenges
			(user_id,digest,binding_hash,auth_version,primary_method,primary_reference,primary_issuer,primary_verified_at,expires_at,administrative,enrollment_required,provider_version,credential_profile,native_audience,native_scope,mfa_policy_revision,factor_method,factor_email_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,LEAST($8::timestamptz,statement_timestamp()),LEAST(statement_timestamp()+$9::double precision*interval '1 second',$18::timestamptz),$10,$11,$12,$13,$14,$15,(SELECT session_revision FROM auth.mfa_settings WHERE singleton),$16,$17)
			ON CONFLICT(user_id) DO UPDATE SET digest=EXCLUDED.digest,binding_hash=EXCLUDED.binding_hash,
			auth_version=EXCLUDED.auth_version,primary_method=EXCLUDED.primary_method,primary_reference=EXCLUDED.primary_reference,
			primary_issuer=EXCLUDED.primary_issuer,primary_verified_at=EXCLUDED.primary_verified_at,administrative=EXCLUDED.administrative,enrollment_required=EXCLUDED.enrollment_required,provider_version=EXCLUDED.provider_version,attempts=0,
			credential_profile=EXCLUDED.credential_profile,native_audience=EXCLUDED.native_audience,native_scope=EXCLUDED.native_scope,mfa_policy_revision=EXCLUDED.mfa_policy_revision,factor_method=EXCLUDED.factor_method,factor_email_id=EXCLUDED.factor_email_id,
			created_at=statement_timestamp(),expires_at=EXCLUDED.expires_at RETURNING expires_at`,
			proof.UserID, digest, binding, proof.AuthVersion, proof.Method, proof.Reference, proof.Issuer, proof.VerifiedAt, ttl.Seconds(), proof.Administrative, result.EnrollmentRequired, proof.ProviderVersion, profile, audience, bound.Scope, factor, emailID, emailExpiry).Scan(&result.ExpiresAt)
		if err != nil {
			return err
		}
		if err := saveLoginCodes(ctx, tx, mail, telegramIntent, profile, audience, bound.Scope, result.ExpiresAt); err != nil {
			return err
		}
		return audit(ctx, tx, proof.UserID, "login_challenge_started")
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *Repository) FindLoginOwner(ctx context.Context, digest, binding string) (accountdomain.UserID, error) {
	return r.findLoginOwner(ctx, digest, binding, "browser")
}

func (r *Repository) FindNativeLoginOwner(ctx context.Context, digest, binding string) (accountdomain.UserID, error) {
	return r.findLoginOwner(ctx, digest, binding, "api")
}

func (r *Repository) findLoginOwner(ctx context.Context, digest, binding, profile string) (accountdomain.UserID, error) {
	var user accountdomain.UserID
	err := r.db.QueryRow(ctx, `SELECT c.user_id FROM auth.mfa_login_challenges c JOIN auth.users u ON u.id=c.user_id
		WHERE c.digest=$1 AND c.binding_hash=$2 AND c.auth_version=u.auth_version AND c.attempts<5
		AND c.mfa_policy_revision=(SELECT session_revision FROM auth.mfa_settings WHERE singleton)
		AND c.credential_profile=$3 AND c.expires_at>clock_timestamp() AND u.status='active' AND u.deleted_at IS NULL`, digest, binding, profile).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrInvalidCode
	}
	return user, err
}

func saveLoginCodes(ctx context.Context, tx pgx.Tx, mail *otpservice.EmailLoginIntent, telegram *service.TelegramLoginIntent, profile string, audience *string, scope []accessdomain.PermissionKey, expiresAt time.Time) error {
	if mail != nil {
		return saveEmailLoginCode(ctx, tx, *mail, profile, audience, scope, expiresAt)
	}
	if telegram != nil {
		_, err := tx.Exec(ctx, `INSERT INTO auth.mfa_telegram_login_codes(digest,bot_id,telegram_user_id,policy_version,verifier) VALUES($1,$2,$3,$4,$5)`, telegram.Digest, telegram.Channel.Bot.ID, telegram.Channel.TelegramID, telegram.Channel.Bot.PolicyVersion, telegram.Verifier)
		return err
	}
	return nil
}
