package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	catalogpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

type RuntimeUsers struct {
	*catalogpostgres.Repository
	registry *projectruntime.Registry
}

func NewRuntimeUsers(repo *catalogpostgres.Repository, registry *projectruntime.Registry) *RuntimeUsers {
	return &RuntimeUsers{Repository: repo, registry: registry}
}

func (r *RuntimeUsers) ListProjectUsers(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, query accountservice.UserListQuery) ([]accountservice.UserSummary, error) {
	var users []accountservice.UserSummary
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operatordomain.Permission{operatordomain.UsersManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		users, err = accountpostgres.ListUsersInTransaction(ctx, tx, query)
		return sqlerrors.Catalog(ctx, err)
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (r *RuntimeUsers) ReadProjectUser(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, id accountdomain.UserID) (accountservice.UserDetail, error) {
	var user accountservice.UserDetail
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operatordomain.Permission{operatordomain.UsersManage, operatordomain.AccessManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		user, err = accountpostgres.ReadUserInTransaction(ctx, tx, id)
		if errors.Is(err, accountdomain.ErrAccountNotFound) || errors.Is(err, accountdomain.ErrUserDirectoryConflict) {
			return err
		}
		return sqlerrors.Catalog(ctx, err)
	})
	if err != nil {
		return accountservice.UserDetail{}, err
	}
	return user, nil
}
