package service

import (
	"context"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

const MaxDirectoryRelations = 32

type userDirectoryRepository interface {
	ListUsers(context.Context, accessservice.Principal, UserListQuery) ([]UserSummary, error)
	ReadUser(context.Context, accessservice.Principal, domain.UserID) (UserDetail, error)
}

type UserDirectory struct{ repo userDirectoryRepository }

func NewUserDirectory(repo userDirectoryRepository) *UserDirectory {
	return &UserDirectory{repo: repo}
}
