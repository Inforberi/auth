package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type roleRepositoryStub struct {
	prepared, executed bool
	err                error
	directoryCalls     int
	roles              []accessdomain.Role
}

func (s *roleRepositoryStub) ListProjectRoles(context.Context, operatordomain.Principal, ProjectRoleQuery) ([]accessdomain.Role, error) {
	s.directoryCalls++
	return s.roles, s.err
}

func (s *roleRepositoryStub) ReadProjectRole(context.Context, operatordomain.Principal, domain.DirectoryTarget, accessdomain.RoleID) (accessdomain.Role, error) {
	s.directoryCalls++
	return accessdomain.Role{}, s.err
}

func (s *roleRepositoryStub) PrepareRoleAssignment(ctx context.Context, actor operatordomain.Principal, _ domain.RoleAssignment) (domain.RoleIntent, error) {
	return s.PrepareRoleCreation(ctx, actor, domain.RoleCreation{})
}

func (s *roleRepositoryStub) ExecuteRoleAssignment(context.Context, operatordomain.Principal, domain.RoleAssignment) (domain.RoleAssignmentResult, error) {
	s.executed = s.prepared
	return domain.RoleAssignmentResult{}, nil
}

func (s *roleRepositoryStub) PrepareRoleCreation(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleIntent, error) {
	s.prepared = true
	return domain.RoleIntent{}, s.err
}

func (s *roleRepositoryStub) ExecuteRoleCreation(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationResult, error) {
	s.executed = s.prepared
	return domain.RoleCreationResult{}, nil
}

func (s *roleRepositoryStub) ReadRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleOutcome, error) {
	return domain.RoleOutcome{}, s.err
}

func (s *roleRepositoryStub) ReconcileRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleOutcome, error) {
	return domain.RoleOutcome{}, s.err
}

func TestRoleCreationRequiresPreparedIntent(t *testing.T) {
	for _, err := range []error{nil, operatordomain.ErrForbidden, domain.ErrConflict} {
		repo := &roleRepositoryStub{err: err}
		_, actual := NewRoles(repo).CreateRole(t.Context(), operatordomain.Principal{}, domain.RoleCreation{})
		if err == nil {
			require.NoError(t, actual)
			require.True(t, repo.executed)
		} else {
			require.ErrorIs(t, actual, err)
			require.False(t, repo.executed)
		}
	}
}

func TestRoleAssignmentRequiresPreparedIntent(t *testing.T) {
	for _, err := range []error{nil, operatordomain.ErrForbidden, domain.ErrConflict} {
		repo := &roleRepositoryStub{err: err}
		_, actual := NewRoles(repo).ChangeRoleAssignment(t.Context(), operatordomain.Principal{}, domain.RoleAssignment{})
		if err == nil {
			require.NoError(t, actual)
			require.True(t, repo.executed)
		} else {
			require.ErrorIs(t, actual, err)
			require.False(t, repo.executed)
		}
	}
}
