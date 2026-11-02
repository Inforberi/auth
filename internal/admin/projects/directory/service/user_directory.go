package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

type UserDirectoryRepository interface {
	ListProjectUsers(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountservice.UserListQuery) ([]accountservice.UserSummary, error)
	ReadProjectUser(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountdomain.UserID) (accountservice.UserDetail, error)
}

type Users struct{ repo UserDirectoryRepository }

func NewUsers(repo UserDirectoryRepository) *Users { return &Users{repo: repo} }

func (s *Users) ListProjectUsers(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, input accountservice.UserListInput) (accountservice.UserPage, error) {
	if err := target.Validate(); err != nil {
		return accountservice.UserPage{}, err
	}
	query, err := accountservice.NormalizeUserList(input)
	if err != nil {
		return accountservice.UserPage{}, err
	}
	users, err := s.repo.ListProjectUsers(ctx, actor, target, query)
	if err != nil {
		return accountservice.UserPage{}, err
	}
	return accountservice.UserPageFromRows(users, query.Limit), nil
}

func (s *Users) ReadProjectUser(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, id accountdomain.UserID) (accountservice.UserDetail, error) {
	if err := target.Validate(); err != nil {
		return accountservice.UserDetail{}, err
	}
	if !accountdomain.ValidUserID(id) {
		return accountservice.UserDetail{}, accountdomain.ErrInvalidUserQuery
	}
	return s.repo.ReadProjectUser(ctx, actor, target, id)
}
