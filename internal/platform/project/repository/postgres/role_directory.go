package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/service"
)

func (r *RuntimeRoles) ListProjectRoles(ctx context.Context, actor operatordomain.Principal, query service.ProjectRoleQuery) ([]accessdomain.Role, error) {
	var roles []accessdomain.Role
	err := r.readDirectory(ctx, actor, query.Target, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		roles, err = accesspostgres.ListRolesInTransaction(ctx, tx, query.AfterKey, query.Limit+1)
		return catalogError(ctx, err)
	})
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func (r *RuntimeRoles) ReadProjectRole(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, id accessdomain.RoleID) (accessdomain.Role, error) {
	var role accessdomain.Role
	err := r.readDirectory(ctx, actor, target, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		role, err = accesspostgres.ReadRoleInTransaction(ctx, tx, id)
		if errors.Is(err, accessdomain.ErrRoleNotFound) {
			return err
		}
		return catalogError(ctx, err)
	})
	if err != nil {
		return accessdomain.Role{}, err
	}
	return role, nil
}
