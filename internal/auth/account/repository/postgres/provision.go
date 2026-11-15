package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
)

func (r *Repository) ProvisionAccount(ctx context.Context, command accountprovisioning.ProvisionCommand) (*accountprovisioning.ProvisionResult, error) {
	var result *accountprovisioning.ProvisionResult
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var err error
		result, err = r.ProvisionInTransaction(ctx, tx, command)
		return err
	})
	return result, err
}

// ProvisionInTransaction lets credential provisioning share the account creation transaction.
func (r *Repository) ProvisionInTransaction(ctx context.Context, tx pgx.Tx, command accountprovisioning.ProvisionCommand) (*accountprovisioning.ProvisionResult, error) {
	if _, err := accesspostgres.AuthorizeMutation(ctx, tx, command.Input.Actor, "", settings.UsersManage); err != nil {
		return nil, err
	}
	result := &accountprovisioning.ProvisionResult{}
	err := provisionAccount(ctx, tx, command, result)
	var sqlErr *pgconn.PgError
	if errors.As(err, &sqlErr) && sqlErr.Code == "23505" && sqlErr.ConstraintName == "user_emails_email_key" {
		return nil, domain.ErrProvisionEmailExists
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func provisionAccount(ctx context.Context, tx pgx.Tx, command accountprovisioning.ProvisionCommand, result *accountprovisioning.ProvisionResult) error {
	input := command.Input
	err := tx.QueryRow(ctx, `INSERT INTO auth.account_provisions(actor_id,request_key,fingerprint)
		VALUES($1,$2,$3) ON CONFLICT(actor_id,request_key) DO NOTHING RETURNING user_id`, input.Actor.UserID, input.IdempotencyKey, command.Fingerprint).Scan(&result.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		var fingerprint string
		if err := tx.QueryRow(ctx, `SELECT user_id,fingerprint FROM auth.account_provisions WHERE actor_id=$1 AND request_key=$2`, input.Actor.UserID, input.IdempotencyKey).Scan(&result.UserID, &fingerprint); err != nil {
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
		if _, err := tx.Exec(ctx, `UPDATE auth.account_provisions SET invitation_email_id=$2 WHERE user_id=$1`, result.UserID, emailID); err != nil {
			return err
		}
	}
	if input.Invite {
		if _, err := tx.Exec(ctx, `UPDATE auth.account_provisions SET last_invited_at=clock_timestamp() WHERE user_id=$1`, result.UserID); err != nil {
			return err
		}
		if err := enqueueInvitation(ctx, tx, result.UserID, emailID, command.Invitation, command.TTL); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.invitation_audit(user_id,actor_id,action,auth_version) VALUES($1,$2,'provisioned',1)`, result.UserID, input.Actor.UserID)
	return err
}

// ProvisionAuthorizedInvitation is called after the platform owner has been authorized in tx.
func ProvisionAuthorizedInvitation(ctx context.Context, tx pgx.Tx, command accountprovisioning.ProvisionCommand, actor domain.UserID, operation string) (domain.UserID, error) {
	command.Input.Actor.UserID = actor
	command.Input.IdempotencyKey = operation
	result := &accountprovisioning.ProvisionResult{}
	err := provisionAccount(ctx, tx, command, result)
	var sqlErr *pgconn.PgError
	if errors.As(err, &sqlErr) && sqlErr.Code == "23505" && sqlErr.ConstraintName == "user_emails_email_key" {
		return "", domain.ErrProvisionEmailExists
	}
	return result.UserID, err
}
