package service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Principal struct {
	UserID accountdomain.UserID
	TokenHash string
}

type Repository interface {
	HasPermission(context.Context, Principal, domain.PermissionKey) (bool, error)
	ReadRole(context.Context, domain.RoleID) (domain.Role, error)
	ListRoles(context.Context, string, int) ([]domain.Role, error)
}

type Service struct {
	repository Repository
	catalog settings.Catalog
}

func New(repository Repository, catalog settings.Catalog) *Service {
	return &Service{repository: repository, catalog: catalog}
}

func (s *Service) Catalog() []settings.Permission { return s.catalog.Permissions() }
