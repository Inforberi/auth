package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	provisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

type PlatformCreation struct {
	OperationID, RealmID, ProjectID string
	ActorID                         domain.UserID
	Invitation                      provisioning.ProvisionCommand
	Temporary                       passwordprovisioning.PreparedTemporaryPassword
	TemporaryResult                 *passwordprovisioning.TemporaryIssueResult
}

func CreatePlatformUser(ctx context.Context, tx pgx.Tx, command PlatformCreation) (domain.UserID, error) {
	// Concurrent retries serialize by operation ID before any new account is allocated.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform.user.create:'||$1::text,0))`, command.OperationID); err != nil {
		return "", err
	}
	var user domain.UserID
	var matches bool
	invite := command.Invitation
	fingerprint, address := invite.Fingerprint, invite.Input.Email
	if command.TemporaryResult != nil {
		fingerprint, address = command.Temporary.Fingerprint, command.Temporary.Email
	}
	err := tx.QueryRow(ctx, `SELECT user_id, project_id=$2 AND realm_id=$3 AND actor_id=$4 AND fingerprint=$5
		FROM auth.platform_user_creations WHERE operation_id=$1`,
		command.OperationID, command.ProjectID, command.RealmID, command.ActorID, fingerprint).Scan(&user, &matches)
	if err == nil {
		if !matches {
			return "", domain.ErrAccountConflict
		}
		if command.TemporaryResult != nil {
			command.TemporaryResult.Reused = true
		}
		return user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	err = tx.QueryRow(ctx, `WITH created AS (
		INSERT INTO auth.users(status) VALUES('pending') RETURNING id
	), profile AS (
		INSERT INTO auth.user_profile(user_id) SELECT id FROM created
	)
	INSERT INTO auth.platform_user_creations(operation_id,project_id,realm_id,actor_id,user_id,fingerprint)
	SELECT $1,$2,$3,$4,id,$5 FROM created RETURNING user_id`,
		command.OperationID, command.ProjectID, command.RealmID, command.ActorID, fingerprint).Scan(&user)
	if err != nil || address == "" {
		return user, err
	}

	var email domain.AddressID
	err = tx.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email) VALUES($1,$2) RETURNING id`, user, address).Scan(&email)
	var sqlErr *pgconn.PgError
	if errors.As(err, &sqlErr) && sqlErr.Code == "23505" && sqlErr.ConstraintName == "user_emails_email_key" {
		return "", domain.ErrProvisionEmailExists
	}
	if err != nil {
		return "", err
	}
	policy, err := settingspostgres.LockPublicPolicy(ctx, tx)
	if err != nil {
		return "", err
	}
	if policy.RequireMethod("password", false) != nil {
		return "", domain.ErrProvisionDisabled
	}
	if command.TemporaryResult != nil {
		command.TemporaryResult.ExpiresAt, err = insertPlatformTemporary(ctx, tx, user, email, command.OperationID, command.Temporary)
		return user, err
	}
	return user, enqueueInvitation(ctx, tx, user, email, invite.Invitation, invite.TTL)
}
