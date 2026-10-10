package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (r *Repository) ProvisionAccount(ctx context.Context, command service.ProvisionCommand) (*service.ProvisionResult, error) {
	result := &service.ProvisionResult{}
	input := command.Input
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var actor domain.UserID
		err := tx.QueryRow(ctx, `SELECT id FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, input.ActorID).Scan(&actor)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrProvisionConflict
		}
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint)
			VALUES($1,$2,$3) ON CONFLICT(actor_id,request_key) DO NOTHING RETURNING user_id`, input.ActorID, input.IdempotencyKey, command.Fingerprint).Scan(&result.UserID)
		if errors.Is(err, pgx.ErrNoRows) {
			var fingerprint string
			if err := tx.QueryRow(ctx, `SELECT user_id,fingerprint FROM auth.account_provisions WHERE actor_id=$1 AND request_key=$2`, input.ActorID, input.IdempotencyKey).Scan(&result.UserID, &fingerprint); err != nil {
				return err
			}
			if fingerprint != command.Fingerprint {
				return domain.ErrProvisionConflict
			}
			result.Reused = true
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.users(id,status) VALUES($1,'pending')`, result.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.user_profile(user_id) VALUES($1)`, result.UserID); err != nil {
			return err
		}
		var emailID domain.AddressID
		if input.Email != "" {
			if err := tx.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email) VALUES($1,$2) RETURNING id`, result.UserID, input.Email).Scan(&emailID); err != nil {
				return err
			}
		}
		if input.Invite {
			if _, err := tx.Exec(ctx, `INSERT INTO auth.account_invitations(digest,user_id,email_id,auth_version,expires_at)
				VALUES($1,$2,$3,1,clock_timestamp()+$4::double precision*interval '1 second')`, command.Invitation.Digest, result.UserID, emailID, command.TTL.Seconds()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO auth.invitation_outbox(digest,payload,expires_at)
				SELECT digest,$2,expires_at FROM auth.account_invitations WHERE digest=$1`, command.Invitation.Digest, command.Invitation.Payload); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.invitation_audit(user_id,actor_id,action,auth_version) VALUES($1,$2,'provisioned',1)`, result.UserID, input.ActorID)
		return err
	})
	var sqlErr *pgconn.PgError
	if errors.As(err, &sqlErr) && sqlErr.Code == "23505" && sqlErr.ConstraintName == "user_emails_email_key" {
		return nil, domain.ErrProvisionEmailExists
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}
