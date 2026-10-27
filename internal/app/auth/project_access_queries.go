package auth

import (
	"context"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *projectAccess) PermissionCatalog(ctx context.Context, actor accessservice.Principal) ([]accesssettings.Permission, error) {
	var result []accesssettings.Permission
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.PermissionCatalog(ctx, actor)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *projectAccess) ListManagedRoles(ctx context.Context, actor accessservice.Principal, afterKey string, limit int) ([]accessdomain.Role, error) {
	var result []accessdomain.Role
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.ListManagedRoles(ctx, actor, afterKey, limit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *projectAccess) ReadManagedRole(ctx context.Context, actor accessservice.Principal, id accessdomain.RoleID) (accessdomain.Role, error) {
	var result accessdomain.Role
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.ReadManagedRole(ctx, actor, id)
		return err
	})
	if err != nil {
		return accessdomain.Role{}, err
	}
	return result, nil
}

func (s *projectAccess) UserAccess(ctx context.Context, actor accessservice.Principal) (accessdomain.UserAccess, error) {
	var result accessdomain.UserAccess
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.UserAccess(ctx, actor)
		return err
	})
	if err != nil {
		return accessdomain.UserAccess{}, err
	}
	return result, nil
}

func (s *projectAccess) AssignmentAccess(ctx context.Context, actor accessservice.Principal, target accountdomain.UserID) (accessdomain.UserAccess, error) {
	var result accessdomain.UserAccess
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.AssignmentAccess(ctx, actor, target)
		return err
	})
	if err != nil {
		return accessdomain.UserAccess{}, err
	}
	return result, nil
}
