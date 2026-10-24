package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type RuntimeUsers struct {
	*Repository
	registry *projectruntime.Registry
}

func NewRuntimeUsers(repo *Repository, registry *projectruntime.Registry) *RuntimeUsers {
	return &RuntimeUsers{Repository: repo, registry: registry}
}

func (r *RuntimeUsers) ListProjectUsers(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, query accountservice.UserListQuery) ([]accountservice.UserSummary, error) {
	var users []accountservice.UserSummary
	err := r.readDirectory(ctx, actor, target, r.registry, []operatordomain.Permission{operatordomain.UsersManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		users, err = accountpostgres.ListUsersInTransaction(ctx, tx, query)
		return catalogError(ctx, err)
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (r *RuntimeUsers) ReadProjectUser(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, id accountdomain.UserID) (accountservice.UserDetail, error) {
	var user accountservice.UserDetail
	err := r.readDirectory(ctx, actor, target, r.registry, []operatordomain.Permission{operatordomain.UsersManage, operatordomain.AccessManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		user, err = accountpostgres.ReadUserInTransaction(ctx, tx, id)
		if errors.Is(err, accountdomain.ErrAccountNotFound) || errors.Is(err, accountdomain.ErrUserDirectoryConflict) {
			return err
		}
		return catalogError(ctx, err)
	})
	if err != nil {
		return accountservice.UserDetail{}, err
	}
	return user, nil
}
