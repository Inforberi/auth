package postgres

import (
	"context"
	"errors"
	"time"

	pgx "github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) EmailLoginChannel(ctx context.Context, proof mfaservice.PrimaryProof) (otpservice.EmailLoginChannel, error) {
	var channel otpservice.EmailLoginChannel
	err := r.db.QueryRow(ctx, `SELECT e.id,e.email::text FROM auth.mfa_email f
 JOIN auth.user_emails e ON e.id=f.email_id AND e.user_id=f.user_id
 JOIN auth.users u ON u.id=f.user_id JOIN auth.password_credentials p ON p.user_id=u.id
 WHERE u.id=$1 AND u.auth_version=$2 AND p.password_hash=$3 AND auth.email_factor_usable(u.id)
 AND NOT auth.has_administrative_access(u.id)`,
		proof.UserID, proof.AuthVersion, proof.Reference).Scan(&channel.ID, &channel.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return channel, domain.ErrProofRequired
	}
	return channel, err
}

func (r *Repository) SaveEmailLoginChallenge(ctx context.Context, input otpservice.EmailLoginIntent, ttl time.Duration) (*mfalogin.LoginChallengeState, error) {
	if input.Proof.Administrative || input.Proof.Method != "password" {
		return nil, domain.ErrProofRequired
	}
	return r.saveLoginChallenge(ctx, input.Proof, input.Target, input.Digest, input.BindingHash, ttl, &input, nil)
}

func lockEmailLoginChannel(ctx context.Context, tx pgx.Tx, proof mfaservice.PrimaryProof, channel otpservice.EmailLoginChannel) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT e.id FROM auth.mfa_email f
 JOIN auth.user_emails e ON e.id=f.email_id AND e.user_id=f.user_id CROSS JOIN auth.mfa_settings p
 WHERE f.user_id=$1 AND e.id=$2 AND e.email=$3 AND p.singleton AND auth.email_factor_usable(f.user_id)
 AND NOT auth.has_administrative_access(f.user_id)
 AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND (activated_at IS NULL OR password_change_required))
 FOR SHARE OF f,e,p`, proof.UserID, channel.ID, channel.Email).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrProofRequired
	}
	return id, err
}

func saveEmailLoginCode(ctx context.Context, tx pgx.Tx, input otpservice.EmailLoginIntent, profile string, audience *string, scope []accessdomain.PermissionKey, expiry time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth.email_login_challenges
 (digest,user_id,email_id,auth_version,verifier,expires_at,purpose,mfa_digest,credential_profile,native_audience,native_scope)
 VALUES($1,$2,$3,$4,$5,$6,'mfa_email_login',$7,$8,$9,$10)`, input.Code.Digest, input.Proof.UserID,
		input.Channel.ID, input.Proof.AuthVersion, input.Code.Verifier, expiry, input.Digest, profile, audience, scope)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.email_login_outbox(digest,payload,expires_at) VALUES($1,$2,$3)`, input.Code.Digest, input.Code.Payload, expiry)
	return err
}
