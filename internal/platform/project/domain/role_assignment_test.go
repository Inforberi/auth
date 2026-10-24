package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoleAssignmentValidation(t *testing.T) {
	base := RoleAssignment{
		OperationID: "f5000000-0000-4000-8000-000000000001", ProjectID: "f5000000-0000-4000-8000-000000000002",
		UserID: "f5000000-0000-4000-8000-000000000003", RoleID: "f5000000-0000-4000-8000-000000000004", Action: RoleGrant,
		ExpectedVersion: 1, ExpectedGeneration: 1, ExpectedRoleVersion: 1, ExpectedAccessVersion: 1, Reason: "role assignment",
	}
	_, err := base.Normalize()
	require.NoError(t, err)
	for _, mutate := range []func(*RoleAssignment){
		func(c *RoleAssignment) { c.Action = RoleCreate }, func(c *RoleAssignment) { c.UserID = "bad" },
		func(c *RoleAssignment) { c.RoleID = "bad" }, func(c *RoleAssignment) { c.OperationID = "" },
		func(c *RoleAssignment) { c.ProjectID = "" }, func(c *RoleAssignment) { c.ExpectedRoleVersion = 0 },
		func(c *RoleAssignment) { c.ExpectedAccessVersion = 0 }, func(c *RoleAssignment) { c.ExpectedGeneration = 0 }, func(c *RoleAssignment) { c.Reason = "" },
	} {
		c := base
		mutate(&c)
		_, err := c.Normalize()
		require.Error(t, err)
	}
}
