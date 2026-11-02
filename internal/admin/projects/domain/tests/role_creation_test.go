package domain_test

import (
	"testing"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func TestRoleCreationNormalize(t *testing.T) {
	command := domain.RoleCreation{
		OperationID: "1c82c477-3a57-4823-8c49-a476550d8a21", ProjectID: "1c82c477-3a57-4823-8c49-a476550d8a22",
		ExpectedVersion: 1, ExpectedGeneration: 1, Key: "editor", Name: "Редактор", Reason: "Создание роли",
		Permissions: []accessdomain.PermissionKey{"users.read", "roles.read"},
	}
	normalized, err := command.Normalize()
	if err != nil || normalized.Permissions[0] != "roles.read" || command.Permissions[0] != "users.read" {
		t.Fatal("canonical request changed caller input", err)
	}
	for _, change := range []func(*domain.RoleCreation){
		func(c *domain.RoleCreation) { c.OperationID = "" },
		func(c *domain.RoleCreation) { c.ProjectID = "" },
		func(c *domain.RoleCreation) { c.ExpectedVersion = 0 },
		func(c *domain.RoleCreation) { c.ExpectedGeneration = 0 },
		func(c *domain.RoleCreation) { c.Reason = " reason " },
		func(c *domain.RoleCreation) { c.Key = "super_admin" },
		func(c *domain.RoleCreation) { c.Permissions = []accessdomain.PermissionKey{"users.read", "users.read"} },
	} {
		invalid := command
		change(&invalid)
		if _, err := invalid.Normalize(); err == nil {
			t.Fatal("invalid request accepted", invalid)
		}
	}
}
