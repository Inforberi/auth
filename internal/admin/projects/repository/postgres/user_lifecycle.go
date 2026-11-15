package postgres

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *Repository) ChangeProjectUser(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, registry *projectruntime.Registry, command accountpostgres.PlatformLifecycle) (accountdomain.AuthVersion, error) {
	if registry == nil {
		return 0, domain.ErrUnavailable
	}
	if err := target.Validate(); err != nil {
		return 0, err
	}
	if !domain.ValidID(domain.ID(command.OperationID)) || !accountdomain.ValidUserID(command.UserID) || command.ExpectedVersion < 1 ||
		(command.Action != "active" && command.Action != "blocked" && command.Action != "delete" &&
			(command.Action != "temporary_password" || command.TemporaryResult == nil) &&
			(command.Action != "initial_email" || command.Email.String() == "")) {
		return 0, domain.ErrInvalidProject
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var result accountdomain.AuthVersion
	err := r.mutate(ctx, actor, operatordomain.UsersManage, func(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
		binding, _, err := lockProjectTarget(ctx, tx, target.ProjectID, target.ExpectedVersion, target.ExpectedGeneration)
		if err != nil {
			return err
		}
		command.ActorID, command.RealmID, command.ProjectID = actor.UserID, string(binding.RealmID), string(binding.ProjectID)
		key := projectruntime.Key{Binding: binding, Version: target.ExpectedVersion, Generation: target.ExpectedGeneration}
		return registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
			return executeProjectTransaction(ctx, db, deadline, new(atomic.Bool), func(ctx context.Context, projectTx pgx.Tx) error {
				if err := schemapostgres.CheckRuntime(ctx, projectTx, binding); err != nil {
					return err
				}
				if err := checkUserAuditGrants(ctx, projectTx, "auth.platform_user_lifecycle", []string{"operation_id", "project_id", "realm_id", "actor_id", "user_id", "action", "expected_version", "auth_version", "email_id"}); err != nil {
					return err
				}
				var err error
				result, err = accountpostgres.ApplyPlatformLifecycle(ctx, projectTx, command)
				switch {
				case errors.Is(err, accountdomain.ErrAccountNotFound), errors.Is(err, accountdomain.ErrAccountConflict),
					errors.Is(err, accountdomain.ErrAccountDeleted), errors.Is(err, accountdomain.ErrLastAdministrator),
					errors.Is(err, accountdomain.ErrEmailBindingConflict), errors.Is(err, passworddomain.ErrTemporaryPasswordDisabled),
					errors.Is(err, passworddomain.ErrInvalidTemporaryPassword), errors.Is(err, passworddomain.ErrTemporaryPasswordCooldown):
					return err
				default:
					return sqlerrors.Catalog(ctx, err)
				}
			})
		})
	})
	if err != nil {
		return 0, err
	}
	return result, nil
}

func checkUserAuditGrants(ctx context.Context, tx pgx.Tx, table string, columns []string) error {
	var present bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present); err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	if !present {
		return domain.ErrUnavailable
	}
	var safe bool
	err := tx.QueryRow(ctx, `SELECT NOT has_table_privilege(current_user,$1,'INSERT,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user,$1,'UPDATE')
		AND NOT has_column_privilege(current_user,$1,'created_at','INSERT')
		AND NOT EXISTS (SELECT 1 FROM unnest($2::text[]) col
		  WHERE NOT has_column_privilege(current_user,$1,col,'INSERT'))`, table, columns).Scan(&safe)
	if err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	if !safe {
		return domain.ErrConflict
	}
	return nil
}
