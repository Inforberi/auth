package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	provisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
)

func (r *Repository) Manage(ctx context.Context, actor domain.Principal, input domain.Management, invite provisioning.ProvisionCommand, freshFor time.Duration) (accountdomain.UserID, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var user accountdomain.UserID
	err := pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		deadline, err := r.AuthorizeMutation(ctx, tx, actor, domain.OperatorsManage, freshFor)
		if err != nil {
			return err
		}
		if err := r.requireOwner(ctx, tx, actor); err != nil {
			return err
		}
		var matches bool
		err = tx.QueryRow(ctx, `SELECT user_id,actor_id=$2 AND action=$3 AND permissions=$4 AND fingerprint=$5
			AND ($6::uuid IS NULL OR user_id=$6) FROM platform.operator_management WHERE operation_id=$1`,
			input.OperationID, actor.UserID, input.Action, input.Permissions, invite.Fingerprint, nullableOperator(input.UserID)).Scan(&user, &matches)
		switch {
		case err == nil:
			if !matches {
				return domain.ErrOperatorConflict
			}
		case errors.Is(err, pgx.ErrNoRows):
			user, err = applyOperatorManagement(ctx, tx, actor, input, invite)
			if err != nil {
				return err
			}
		default:
			return err
		}
		var fresh bool
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
			return err
		}
		if !fresh {
			return domain.ErrFreshAuthRequired
		}
		return nil
	})
	if err == nil {
		return user, nil
	}
	for _, safe := range []error{domain.ErrForbidden, domain.ErrFreshAuthRequired, domain.ErrOwnerProtected, domain.ErrOperatorConflict, accountdomain.ErrProvisionEmailExists, accountdomain.ErrProvisionConflict} {
		if errors.Is(err, safe) {
			return "", safe
		}
	}
	return "", errors.Join(domain.ErrUnavailable, ctx.Err())
}

func (r *Repository) requireOwner(ctx context.Context, tx pgx.Tx, actor domain.Principal) error {
	var owner bool
	if err := tx.QueryRow(ctx, `SELECT first_operator_id=$2 FROM platform.operator_realm WHERE id=$1`, r.realm, actor.UserID).Scan(&owner); err != nil {
		return err
	}
	if !owner {
		return domain.ErrForbidden
	}
	return nil
}

func nullableOperator(user accountdomain.UserID) any {
	if user == "" {
		return nil
	}
	return user
}
