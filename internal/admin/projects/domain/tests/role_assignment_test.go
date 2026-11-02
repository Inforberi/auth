package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func TestRoleAssignmentValidation(t *testing.T) {
	base := domain.RoleAssignment{
		OperationID: "f5000000-0000-4000-8000-000000000001", ProjectID: "f5000000-0000-4000-8000-000000000002",
		UserID: "f5000000-0000-4000-8000-000000000003", RoleID: "f5000000-0000-4000-8000-000000000004", Action: domain.RoleGrant,
		ExpectedVersion: 1, ExpectedGeneration: 1, ExpectedRoleVersion: 1, ExpectedAccessVersion: 1, Reason: "role assignment",
	}
	_, err := base.Normalize()
	require.NoError(t, err)
	for _, mutate := range []func(*domain.RoleAssignment){
		func(c *domain.RoleAssignment) { c.Action = domain.RoleCreate }, func(c *domain.RoleAssignment) { c.UserID = "bad" },
		func(c *domain.RoleAssignment) { c.RoleID = "bad" }, func(c *domain.RoleAssignment) { c.OperationID = "" },
		func(c *domain.RoleAssignment) { c.ProjectID = "" }, func(c *domain.RoleAssignment) { c.ExpectedRoleVersion = 0 },
		func(c *domain.RoleAssignment) { c.ExpectedAccessVersion = 0 }, func(c *domain.RoleAssignment) { c.ExpectedGeneration = 0 }, func(c *domain.RoleAssignment) { c.Reason = "" },
	} {
		c := base
		mutate(&c)
		_, err := c.Normalize()
		require.Error(t, err)
	}
}
