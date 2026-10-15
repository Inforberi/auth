package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func (r *TemporaryPasswordRepo) ProvisionTemporary(ctx context.Context, command accountservice.ProvisionCommand, credential domain.TemporaryCredential, ttl time.Duration) (*service.TemporaryIssueResult, error) {
	result := &service.TemporaryIssueResult{}
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		account, err := r.provision(ctx, tx, command)
		if err != nil {
			return err
		}
		result.UserID, result.Reused = account.UserID, account.Reused
		if result.Reused {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.account_provisions SET password_change_required=true,temporary_password_issued_at=clock_timestamp() WHERE user_id=$1`, result.UserID); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.temporary_password_credentials(user_id,email_id,password_hash,secret_digest,auth_version,expires_at)
			SELECT p.user_id,p.invitation_email_id,$2,$3,1,clock_timestamp()+$4::double precision*interval '1 second'
			FROM auth.account_provisions p WHERE p.user_id=$1 RETURNING expires_at`, result.UserID, credential.PasswordHash, credential.SecretDigest, ttl.Seconds()).Scan(&result.ExpiresAt)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,actor_id,event,auth_version) VALUES($1,$2,'temporary_password_issued',1)`, result.UserID, command.Input.Actor.UserID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
