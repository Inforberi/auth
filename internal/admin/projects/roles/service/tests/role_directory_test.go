package service_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	roleservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/service"
)

func TestProjectRoleDirectoryValidation(t *testing.T) {
	target := domain.DirectoryTarget{ProjectID: "11111111-1111-4111-8111-111111111111", ExpectedVersion: 1, ExpectedGeneration: 2}
	for _, query := range []roleservice.ProjectRoleQuery{
		{Target: domain.DirectoryTarget{}, Limit: 50},
		{Target: target, Limit: 0},
		{Target: target, Limit: 101},
		{Target: target, Limit: 50, AfterKey: "invalid key"},
	} {
		repo := &roleRepositoryStub{}
		_, err := roleservice.NewRoles(repo).ListProjectRoles(t.Context(), operatordomain.Principal{}, query)
		require.Error(t, err)
		require.Zero(t, repo.directoryCalls)
	}
	repo := &roleRepositoryStub{}
	_, err := roleservice.NewRoles(repo).ReadProjectRole(t.Context(), operatordomain.Principal{}, target, "bad-id")
	require.ErrorIs(t, err, accessdomain.ErrInvalidRole)
	require.Zero(t, repo.directoryCalls)
}

func TestProjectRoleDirectoryPaginationAndFailure(t *testing.T) {
	target := domain.DirectoryTarget{ProjectID: "11111111-1111-4111-8111-111111111111", ExpectedVersion: 1, ExpectedGeneration: 2}
	repo := &roleRepositoryStub{roles: []accessdomain.Role{{Key: "a"}, {Key: "b"}, {Key: "c"}}}
	page, err := roleservice.NewRoles(repo).ListProjectRoles(t.Context(), operatordomain.Principal{}, roleservice.ProjectRoleQuery{Target: target, Limit: 2})
	require.NoError(t, err)
	require.Len(t, page.Roles, 2)
	require.Equal(t, "b", page.NextAfterKey)
	repo.err = operatordomain.ErrForbidden
	page, err = roleservice.NewRoles(repo).ListProjectRoles(t.Context(), operatordomain.Principal{}, roleservice.ProjectRoleQuery{Target: target, Limit: 2})
	require.ErrorIs(t, err, repo.err)
	require.Empty(t, page.Roles)
	repo.err, repo.roles = nil, nil
	page, err = roleservice.NewRoles(repo).ListProjectRoles(t.Context(), operatordomain.Principal{}, roleservice.ProjectRoleQuery{Target: target, Limit: 2})
	require.NoError(t, err)
	require.NotNil(t, page.Roles)
	require.Empty(t, page.NextAfterKey)
}
