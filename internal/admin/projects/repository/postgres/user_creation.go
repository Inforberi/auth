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
)

func (r *Repository) CreateProjectUser(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, registry *projectruntime.Registry, command accountpostgres.PlatformCreation) (accountdomain.UserID, error) {
	if err := target.Validate(); err != nil {
		return "", err
	}
	if !domain.ValidID(domain.ID(command.OperationID)) {
		return "", domain.ErrInvalidProject
	}
	if registry == nil {
		return "", domain.ErrUnavailable
	}
	var user accountdomain.UserID
	err := r.mutate(ctx, actor, operatordomain.UsersManage, func(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
		binding, _, err := lockProjectTarget(ctx, tx, target.ProjectID, target.ExpectedVersion, target.ExpectedGeneration)
		if err != nil {
			return err
		}
		key := projectruntime.Key{Binding: binding, Version: target.ExpectedVersion, Generation: target.ExpectedGeneration}
		return registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
			return executeProjectTransaction(ctx, db, deadline, new(atomic.Bool), func(ctx context.Context, projectTx pgx.Tx) error {
				if err := schemapostgres.CheckRuntime(ctx, projectTx, binding); err != nil {
					return err
				}
				if err := checkUserAuditGrants(ctx, projectTx, "auth.platform_user_creations", []string{"operation_id", "project_id", "realm_id", "actor_id", "user_id", "fingerprint"}); err != nil {
					return err
				}
				command.ActorID = actor.UserID
				command.RealmID, command.ProjectID = string(binding.RealmID), string(binding.ProjectID)
				user, err = accountpostgres.CreatePlatformUser(ctx, projectTx, command)
				if errors.Is(err, accountdomain.ErrAccountConflict) || errors.Is(err, accountdomain.ErrProvisionDisabled) || errors.Is(err, accountdomain.ErrProvisionEmailExists) {
					return err
				}
				return sqlerrors.Catalog(ctx, err)
			})
		})
	})
	if err != nil {
		return "", err
	}
	return user, nil
}

func (r *Repository) ResolveProjectTarget(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, permission operatordomain.Permission) (DirectoryRuntime, error) {
	var selected DirectoryRuntime
	if err := target.Validate(); err != nil {
		return selected, err
	}
	err := r.mutate(ctx, actor, permission, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		binding, _, err := lockProjectTarget(ctx, tx, target.ProjectID, target.ExpectedVersion, target.ExpectedGeneration)
		if err != nil {
			return err
		}
		selected.Key = projectruntime.Key{Binding: binding, Version: target.ExpectedVersion, Generation: target.ExpectedGeneration}
		return sqlerrors.Catalog(ctx, tx.QueryRow(ctx, `SELECT origin FROM platform.projects WHERE id=$1`, target.ProjectID).Scan(&selected.Origin))
	})
	return selected, err
}
