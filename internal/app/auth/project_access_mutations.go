package auth

import (
	"context"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
)

func (s *projectAccess) CreateRole(ctx context.Context, input accessservice.CreateRoleInput) (accessdomain.Role, error) {
	var result accessdomain.Role
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.CreateRole(ctx, input)
		return err
	})
	if err != nil {
		return accessdomain.Role{}, err
	}
	return result, nil
}

func (s *projectAccess) UpdateRole(ctx context.Context, input accessservice.UpdateRoleInput) (accessdomain.Role, error) {
	var result accessdomain.Role
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.UpdateRole(ctx, input)
		return err
	})
	if err != nil {
		return accessdomain.Role{}, err
	}
	return result, nil
}

func (s *projectAccess) ChangeAssignment(ctx context.Context, input accessservice.AssignmentInput) (int64, error) {
	var result int64
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.ChangeAssignment(ctx, input)
		return err
	})
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (s *projectAccess) ChangeAdministrator(ctx context.Context, input accessservice.AdministratorInput) (int64, error) {
	var result int64
	err := s.use(ctx, func(ctx context.Context, service *accessservice.Service) error {
		var err error
		result, err = service.ChangeAdministrator(ctx, input)
		return err
	})
	if err != nil {
		return 0, err
	}
	return result, nil
}
