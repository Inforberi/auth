package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type CreateRoleInput struct {
	Actor       Principal
	Key         string
	Name        string
	Description string
	Permissions []domain.PermissionKey
	MFARequired *bool
}

type UpdateRoleInput struct {
	CreateRoleInput
	RoleID          domain.RoleID
	ExpectedVersion int64
}

func (s *Service) CreateRole(ctx context.Context, input CreateRoleInput) (domain.Role, error) {
	if err := s.validateRoleInput(input); err != nil {
		return domain.Role{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repository.CreateRole(ctx, input)
}

func (s *Service) UpdateRole(ctx context.Context, input UpdateRoleInput) (domain.Role, error) {
	if !accountdomain.ValidUserID(accountdomain.UserID(input.RoleID)) || input.ExpectedVersion < 1 {
		return domain.Role{}, domain.ErrInvalidRole
	}
	if err := s.validateRoleInput(input.CreateRoleInput); err != nil {
		return domain.Role{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repository.UpdateRole(ctx, input)
}

func (s *Service) validateRoleInput(input CreateRoleInput) error {
	if !validPrincipal(input.Actor) {
		return domain.ErrForbidden
	}
	if err := domain.ValidateRole(input.Key, input.Name, input.Description, input.Permissions); err != nil {
		return err
	}
	for _, permission := range input.Permissions {
		if !s.catalog.Contains(permission) {
			return domain.ErrInvalidPermission
		}
	}
	return nil
}
