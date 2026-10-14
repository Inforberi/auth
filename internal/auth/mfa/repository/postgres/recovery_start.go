package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) SaveRecoveryRequest(ctx context.Context, input service.RecoveryRequest) (*service.RecoveryCandidate, error) {
	var result service.RecoveryCandidate
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		proof, err := lockLoginChallenge(ctx, tx, input.Digest, input.BindingHash)
		if err != nil {
			return err
		}
		if proof.UserID != input.UserID || input.AllowPrimary == nil || !input.AllowPrimary(proof.Method, proof.Issuer) {
			return domain.ErrInvalidCode
		}
		if err := requireLoginPrimary(ctx, tx, *proof); err != nil {
			if errors.Is(err, domain.ErrProofRequired) {
				return domain.ErrInvalidCode
			}
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.mfa_recovery_requests(user_id,challenge_digest,auth_version,secret,expires_at)
			SELECT $1,$2,$3,$4,c.expires_at FROM auth.mfa_login_challenges c
			WHERE c.user_id=$1 AND c.digest=$2 AND c.expires_at>clock_timestamp()
			AND EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
			ON CONFLICT(user_id) DO UPDATE SET request_id=gen_random_uuid(),challenge_digest=EXCLUDED.challenge_digest,
			auth_version=EXCLUDED.auth_version,secret=EXCLUDED.secret,state='pending',attempts=0,
			operator_oid=NULL,operator_name=NULL,approved_at=NULL,environment=NULL,reason=NULL,
			created_at=statement_timestamp(),expires_at=EXCLUDED.expires_at RETURNING request_id,expires_at`,
			proof.UserID, input.Digest, proof.AuthVersion, input.Secret).Scan(&result.RequestID, &result.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidCode
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.mfa_audit(user_id,event,request_id,auth_version)
			VALUES($1,'recovery_requested',$2,$3)`, proof.UserID, result.RequestID, proof.AuthVersion)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
