package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
)

type PlatformLifecycle struct {
	OperationID, RealmID, ProjectID string
	UserID, ActorID                 domain.UserID
	Action                          string
	ExpectedVersion                 domain.AuthVersion
	Email                           domain.Email
	Temporary                       passwordprovisioning.PreparedTemporaryPassword
	TemporaryResult                 *passwordprovisioning.TemporaryIssueResult
}

// ApplyPlatformLifecycle requires a transaction for a verified project binding and fresh platform authority.
func ApplyPlatformLifecycle(ctx context.Context, tx pgx.Tx, c PlatformLifecycle) (domain.AuthVersion, error) {
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return 0, err
	}
	var version domain.AuthVersion
	var matches bool
	err := tx.QueryRow(ctx, `SELECT auth_version, project_id=$2 AND realm_id=$3 AND actor_id=$4
		AND user_id=$5 AND action=$6 AND expected_version=$7
		AND ($6<>'initial_email' OR EXISTS(SELECT 1 FROM auth.user_emails e WHERE e.id=l.email_id AND e.email=$8))
		FROM auth.platform_user_lifecycle l WHERE operation_id=$1`,
		c.OperationID, c.ProjectID, c.RealmID, c.ActorID, c.UserID, c.Action, c.ExpectedVersion, c.Email.String()).Scan(&version, &matches)
	if err == nil {
		if !matches {
			return 0, domain.ErrAccountConflict
		}
		if c.TemporaryResult != nil {
			c.TemporaryResult.Reused = true
		}
		return version, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	var emailID any
	switch c.Action {
	case "initial_email":
		var address domain.AddressID
		version, address, err = bindPlatformInitialEmail(ctx, tx, c)
		emailID = address
	case "temporary_password":
		version, err = reissuePlatformTemporary(ctx, tx, c)
	case "delete":
		version, err = applyDeletion(ctx, tx, domain.AccountDeletion{UserID: c.UserID, ExpectedVersion: c.ExpectedVersion}, false)
	default:
		version, err = applyStatus(ctx, tx, domain.StatusChange{UserID: c.UserID, Status: domain.Status(c.Action), ExpectedVersion: c.ExpectedVersion}, false)
	}
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.platform_user_lifecycle(operation_id,project_id,realm_id,actor_id,user_id,action,expected_version,auth_version,email_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.OperationID, c.ProjectID, c.RealmID, c.ActorID, c.UserID, c.Action, c.ExpectedVersion, version, emailID)
	return version, err
}
