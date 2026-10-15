package service

import (
	"context"
	"slices"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *Service) PermissionCatalog(ctx context.Context, actor Principal) ([]settings.Permission, error) {
	if err := s.authorizeRoleRead(ctx, actor); err != nil {
		return nil, err
	}
	return s.Catalog(), nil
}

func (s *Service) ReadManagedRole(ctx context.Context, actor Principal, id domain.RoleID) (domain.Role, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.authorizeRoleRead(ctx, actor); err != nil {
		return domain.Role{}, err
	}
	return s.ReadRole(ctx, id)
}

func (s *Service) ListManagedRoles(ctx context.Context, actor Principal, afterKey string, limit int) ([]domain.Role, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.authorizeRoleRead(ctx, actor); err != nil {
		return nil, err
	}
	return s.ListRoles(ctx, afterKey, limit)
}

func (s *Service) authorizeRoleRead(ctx context.Context, actor Principal) error {
	access, err := s.UserAccess(ctx, actor)
	if err != nil {
		return err
	}
	if !slices.Contains(access.Permissions, settings.RolesManage) && !slices.Contains(access.Permissions, settings.AssignmentsManage) {
		return domain.ErrForbidden
	}
	return nil
}

func (s *Service) AssignmentAccess(ctx context.Context, actor Principal, target accountdomain.UserID) (domain.UserAccess, error) {
	if !validPrincipal(actor) {
		return domain.UserAccess{}, domain.ErrForbidden
	}
	if !accountdomain.ValidUserID(target) {
		return domain.UserAccess{}, domain.ErrInvalidRole
	}
	permissions := s.Catalog()
	keys := make([]domain.PermissionKey, 0, len(permissions))
	for _, permission := range permissions {
		keys = append(keys, permission.Key)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repository.ReadAssignments(ctx, actor, target, keys)
}
