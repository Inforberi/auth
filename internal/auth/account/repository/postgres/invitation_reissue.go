package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (r *Repository) InvitationAddress(ctx context.Context, actor accessservice.Principal, user domain.UserID) (string, error) {
	var email string
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, actor, string(user), settings.UsersManage); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT e.email FROM auth.account_provisions p
		JOIN auth.user_emails e ON e.user_id=p.user_id AND e.id=p.invitation_email_id WHERE p.user_id=$1`, user).Scan(&email)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrInvalidInvitation
	}
	return email, err
}

func (r *Repository) ReissueInvitation(ctx context.Context, command service.InvitationReissueCommand) (*service.ProvisionResult, error) {
	result := &service.ProvisionResult{UserID: command.Input.UserID}
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, command.Input.Actor, string(command.Input.UserID), settings.UsersManage); err != nil {
			return err
		}
		var previous domain.UserID
		err := tx.QueryRow(ctx, `SELECT user_id FROM auth.invitation_reissues WHERE actor_id=$1 AND request_key=$2`, command.Input.Actor.UserID, command.Input.IdempotencyKey).Scan(&previous)
		if err == nil {
			if previous != command.Input.UserID {
				return domain.ErrProvisionConflict
			}
			result.Reused = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return replaceInvitation(ctx, tx, command)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func replaceInvitation(ctx context.Context, tx pgx.Tx, c service.InvitationReissueCommand) error {
	var emailID domain.AddressID
	var version domain.AuthVersion
	var ready bool
	err := tx.QueryRow(ctx, `SELECT e.id,u.auth_version,
		(p.last_invited_at IS NULL OR p.last_invited_at+$3::double precision*interval '1 second'<=clock_timestamp())
		FROM auth.account_provisions p JOIN auth.users u ON u.id=p.user_id
		JOIN auth.user_emails e ON e.user_id=u.id AND e.id=p.invitation_email_id
		WHERE u.id=$1 AND u.status='pending' AND u.deleted_at IS NULL AND p.activated_at IS NULL AND NOT p.password_change_required
		AND e.email=$2 AND e.verified_at IS NULL
		AND NOT EXISTS(SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id=u.id)
		FOR UPDATE OF e`, c.Input.UserID, c.Email, c.Cooldown.Seconds()).Scan(&emailID, &version, &ready)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrInvalidInvitation
	}
	if err != nil {
		return err
	}
	if !ready {
		return domain.ErrInvitationCooldown
	}
	// The unique command key serializes retries even when they target different users.
	var stored domain.UserID
	err = tx.QueryRow(ctx, `INSERT INTO auth.invitation_reissues(actor_id,request_key,user_id)
		VALUES($1,$2,$3) ON CONFLICT(actor_id,request_key) DO NOTHING RETURNING user_id`, c.Input.Actor.UserID, c.Input.IdempotencyKey, c.Input.UserID).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrProvisionConflict
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.account_invitations WHERE user_id=$1`, c.Input.UserID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.account_invitations(digest,user_id,email_id,auth_version,expires_at)
		VALUES($1,$2,$3,$4,clock_timestamp()+$5::double precision*interval '1 second')`, c.Invitation.Digest, c.Input.UserID, emailID, version, c.TTL.Seconds()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.invitation_outbox(digest,payload,expires_at)
		SELECT digest,$2,expires_at FROM auth.account_invitations WHERE digest=$1`, c.Invitation.Digest, c.Invitation.Payload); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.account_provisions SET last_invited_at=clock_timestamp() WHERE user_id=$1`, c.Input.UserID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.invitation_audit(user_id,actor_id,action,auth_version) VALUES($1,$2,'reissued',$3)`, c.Input.UserID, c.Input.Actor.UserID, version)
	return err
}
