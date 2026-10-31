package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

func checkPlatformRoleIsolation(t *testing.T, ctx context.Context, pair preparedHTTPProjects, f projectIsolationHTTP) {
	t.Helper()
	managed, actor := isolationPlatformOperator(t, ctx, pair)
	permissions, err := accesssettings.NewCatalog([]accesssettings.Permission{{Key: "reports.read", Name: "Read"}})
	require.NoError(t, err)
	runtime := catalog.NewRuntimeRoles(managed, f.deps.Registry, permissions)
	operations := []string{
		"f8900000-0000-4000-8000-000000000011", "f8900000-0000-4000-8000-000000000012",
		"f8900000-0000-4000-8000-000000000021", "f8900000-0000-4000-8000-000000000022",
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, db := range f.databases {
			for _, table := range []string{"platform_role_assignments", "platform_role_creations"} {
				_, err := db.Exec(cleanup, `DELETE FROM auth.`+table+` WHERE operation_id=ANY($1::uuid[])`, operations)
				require.NoError(t, err)
			}
			_, err := db.Exec(cleanup, `DELETE FROM auth.access_audit WHERE actor_id=$1`, actor.UserID)
			require.NoError(t, err)
			_, err = db.Exec(cleanup, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id IN
 (SELECT id FROM auth.roles WHERE key='http_platform_reader')`, httpIsolationUser)
			require.NoError(t, err)
			_, err = db.Exec(cleanup, `DELETE FROM auth.roles WHERE key='http_platform_reader'`)
			require.NoError(t, err)
		}
		for _, table := range []string{"project_role_outcomes", "project_role_admissions", "project_role_intents"} {
			_, err := pair.admin.Exec(cleanup, `DELETE FROM platform.`+table+` WHERE operation_id=ANY($1::uuid[])`, operations)
			require.NoError(t, err)
		}
	})
	var commands [2]domain.RoleCreation
	var roles [2]accessdomain.Role
	for i, key := range f.projects {
		commands[i] = domain.RoleCreation{
			OperationID: domain.ID(operations[i]), ProjectID: key.Binding.ProjectID,
			ExpectedVersion: key.Version, ExpectedGeneration: key.Generation,
			Key: "http_platform_reader", Name: "Platform reader", Permissions: []accessdomain.PermissionKey{"reports.read"}, Reason: "Two-project bridge isolation",
		}
		_, err := managed.PrepareRoleCreation(ctx, actor, commands[i])
		require.NoError(t, err)
		created, err := runtime.ExecuteRoleCreation(ctx, actor, commands[i])
		require.NoError(t, err)
		require.True(t, created.CatalogRecorded)
		roles[i] = created.Role
	}
	require.NotEqual(t, roles[0].ID, roles[1].ID)
	wrongProject := commands[0]
	wrongProject.ProjectID = commands[1].ProjectID
	_, err = managed.PrepareRoleCreation(ctx, actor, wrongProject)
	require.ErrorIs(t, err, domain.ErrConflict, "an operation ID cannot be rebound to B")
	_, err = runtime.ExecuteRoleCreation(ctx, actor, wrongProject)
	require.ErrorIs(t, err, domain.ErrConflict)
	_, err = managed.ReadRoleOutcome(ctx, actor, commands[1].ProjectID, commands[0].OperationID)
	require.ErrorIs(t, err, domain.ErrNotFound)
	_, err = managed.ReconcileRoleOutcome(ctx, actor, commands[1].ProjectID, commands[0].OperationID, f.deps.Registry)
	require.ErrorIs(t, err, domain.ErrNotFound)
	replayed, err := runtime.ExecuteRoleCreation(ctx, actor, commands[0])
	require.NoError(t, err)
	require.True(t, replayed.Replayed)
	require.Equal(t, roles[0].ID, replayed.Role.ID)

	for i, key := range f.projects {
		var accessVersion int64
		require.NoError(t, f.databases[i].QueryRow(ctx, `SELECT access_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&accessVersion))
		command := domain.RoleAssignment{
			OperationID: domain.ID(operations[i+2]), ProjectID: key.Binding.ProjectID,
			ExpectedVersion: key.Version, ExpectedGeneration: key.Generation, Action: domain.RoleGrant,
			UserID: accountdomain.UserID(httpIsolationUser), RoleID: roles[i].ID,
			ExpectedRoleVersion: roles[i].Version, ExpectedAccessVersion: accessVersion, Reason: "Two-project grant isolation",
		}
		_, err := managed.PrepareRoleAssignment(ctx, actor, command)
		require.NoError(t, err)
		granted, err := runtime.ExecuteRoleAssignment(ctx, actor, command)
		require.NoError(t, err)
		require.True(t, granted.CatalogRecorded)
		require.True(t, granted.Changed)
		require.Equal(t, accessVersion+1, granted.AccessVersion)
		outcome, err := managed.ReadRoleOutcome(ctx, actor, command.ProjectID, command.OperationID)
		require.NoError(t, err)
		require.True(t, outcome.Committed)
		require.Equal(t, roles[i].ID, outcome.Role.ID)
		require.Equal(t, granted.AccessVersion, outcome.AccessVersion)
		foreign := command
		foreign.ProjectID = f.projects[1-i].Binding.ProjectID
		_, err = managed.PrepareRoleAssignment(ctx, actor, foreign)
		require.ErrorIs(t, err, domain.ErrConflict)
		_, err = runtime.ExecuteRoleAssignment(ctx, actor, foreign)
		require.ErrorIs(t, err, domain.ErrConflict)
	}
	for i, db := range f.databases {
		var local, foreign int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FILTER(WHERE role_id=$2),count(*) FILTER(WHERE role_id=$3)
 FROM auth.user_roles WHERE user_id=$1`, httpIsolationUser, roles[i].ID, roles[1-i].ID).Scan(&local, &foreign))
		require.Equal(t, 1, local)
		require.Zero(t, foreign)
	}
}
