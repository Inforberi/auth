package service

import (
	"context"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type ProjectRoleQuery struct {
	Target   domain.DirectoryTarget
	AfterKey string
	Limit    int
}

type ProjectRolePage struct {
	Roles        []accessdomain.Role
	NextAfterKey string
}

func (s *Roles) ListProjectRoles(ctx context.Context, actor operatordomain.Principal, query ProjectRoleQuery) (ProjectRolePage, error) {
	if err := query.Target.Validate(); err != nil {
		return ProjectRolePage{}, err
	}
	if query.Limit < 1 || query.Limit > 100 || (query.AfterKey != "" && !accessdomain.ValidKey(query.AfterKey)) {
		return ProjectRolePage{}, accessdomain.ErrInvalidRole
	}
	roles, err := s.repo.ListProjectRoles(ctx, actor, query)
	if err != nil {
		return ProjectRolePage{}, err
	}
	page := ProjectRolePage{Roles: roles}
	if len(roles) > query.Limit {
		page.Roles = roles[:query.Limit]
		page.NextAfterKey = page.Roles[len(page.Roles)-1].Key
	}
	if page.Roles == nil {
		page.Roles = []accessdomain.Role{}
	}
	return page, nil
}

func (s *Roles) ReadProjectRole(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, role accessdomain.RoleID) (accessdomain.Role, error) {
	if err := target.Validate(); err != nil {
		return accessdomain.Role{}, err
	}
	if !accountdomain.ValidUserID(accountdomain.UserID(role)) {
		return accessdomain.Role{}, accessdomain.ErrInvalidRole
	}
	return s.repo.ReadProjectRole(ctx, actor, target, role)
}
