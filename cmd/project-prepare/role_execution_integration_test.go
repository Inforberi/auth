package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

func projectRoleDrill(t *testing.T, physical *pgx.Conn, runtime *pgxpool.Pool, binding credentials.Binding) {
	t.Helper()
	ctx := t.Context()
	cfg := physical.Config().Copy()
	cfg.Database, _, _ = (domain.PreparationReservation{ProjectID: binding.ProjectID, ReservationID: binding.ReservationID}).ResourceNames()
	admin, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		// Only this disposable drill's prefixed roles/receipts; restore empty onboarding fixture.
		_, err := admin.Exec(cleanup, `DELETE FROM auth.platform_role_creations WHERE role_id IN
			(SELECT id FROM auth.roles WHERE key IN ('platform_drill_editor','platform_drill_new','platform_drill_parallel','platform_drill_failed','platform_drill_rollback'));
			DELETE FROM auth.roles WHERE key IN ('platform_drill_editor','platform_drill_new','platform_drill_parallel','platform_drill_failed','platform_drill_rollback')`)
		require.NoError(t, err)
		require.NoError(t, admin.Close(cleanup))
	})
	permissions, err := settings.NewCatalog(nil)
	require.NoError(t, err)
	actor := domain.PlatformActor{RealmID: binding.RealmID, UserID: "e2000000-0000-4000-8000-000000000088", AdmissionID: "e2000000-0000-4000-8000-000000000080"}
	command := domain.RoleCreation{
		OperationID: "e2000000-0000-4000-8000-000000000081", ProjectID: binding.ProjectID,
		ExpectedVersion: 3, ExpectedGeneration: 3, Key: "platform_drill_editor", Name: "Редактор", Reason: "SQL drill",
		Permissions: []accessdomain.PermissionKey{settings.UsersRead, settings.RolesManage},
	}
	// This tests project persistence, not platform authorization or public dispatch.
	apply := func(a domain.PlatformActor, b credentials.Binding, c domain.RoleCreation, ready bool) (domain.RoleCreationResult, error) {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		tx, err := runtime.Begin(bounded)
		if err != nil {
			return domain.RoleCreationResult{}, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		result, err := catalog.CreatePlatformRoleInTransaction(bounded, tx, a, b, c, permissions, ready)
		if err != nil {
			return domain.RoleCreationResult{}, err
		}
		if err := tx.Commit(bounded); err != nil {
			return domain.RoleCreationResult{}, err
		}
		return result, nil
	}
	first, err := apply(actor, binding, command, true)
	require.NoError(t, err)
	require.False(t, first.Replayed)
	require.Equal(t, int64(1), first.Role.Version)
	var xmin string
	require.NoError(t, runtime.QueryRow(ctx, `SELECT xmin::text FROM auth.platform_role_creations WHERE operation_id=$1`, command.OperationID).Scan(&xmin))
	command.Permissions = []accessdomain.PermissionKey{settings.RolesManage, settings.UsersRead}
	replay, err := apply(actor, binding, command, true)
	require.NoError(t, err)
	require.True(t, replay.Replayed)
	require.Equal(t, first.Role, replay.Role)
	var safe bool
	require.NoError(t, runtime.QueryRow(ctx, `SELECT xmin::text=$1 AND actor_id=$2 AND realm_id=$3
		AND NOT EXISTS(SELECT 1 FROM auth.users) FROM auth.platform_role_creations WHERE operation_id=$4`, xmin,
		actor.UserID, actor.RealmID, command.OperationID).Scan(&safe))
	require.True(t, safe, "replay must not create a project user or rewrite audit")
	wrong := command
	wrong.Name = "Другой запрос"
	_, err = apply(actor, binding, wrong, true)
	require.ErrorIs(t, err, domain.ErrConflict)
	other := actor
	other.UserID = "e2000000-0000-4000-8000-000000000089"
	_, err = apply(other, binding, command, true)
	require.ErrorIs(t, err, domain.ErrConflict)
	wrongBinding := binding
	wrongBinding.DatabaseOID++
	_, err = apply(actor, wrongBinding, command, true)
	require.ErrorIs(t, err, domain.ErrConflict)
	wrongBinding = binding
	wrongBinding.ReservationID = "e2000000-0000-4000-8000-000000000089"
	_, err = apply(actor, wrongBinding, command, true)
	require.ErrorIs(t, err, domain.ErrConflict)
	newCommand := command
	newCommand.OperationID, newCommand.Key = "e2000000-0000-4000-8000-000000000082", "platform_drill_new"
	newCommand.Permissions = []accessdomain.PermissionKey{"unknown.permission"}
	_, err = apply(actor, binding, newCommand, true)
	require.ErrorIs(t, err, accessdomain.ErrInvalidPermission)
	newCommand.Permissions, newCommand.MFARequired = nil, true
	_, err = apply(actor, binding, newCommand, false)
	require.ErrorIs(t, err, accessdomain.ErrMFANotReady)
	_, err = apply(actor, binding, newCommand, true)
	require.NoError(t, err)
	newCommand.OperationID = "e2000000-0000-4000-8000-000000000083"
	newCommand.Key = "super_admin"
	_, err = apply(actor, binding, newCommand, true)
	require.ErrorIs(t, err, accessdomain.ErrInvalidRole)

	t.Run("concurrent retry", func(t *testing.T) {
		c := command
		c.OperationID, c.Key = "e2000000-0000-4000-8000-000000000084", "platform_drill_parallel"
		var wg sync.WaitGroup
		results := make(chan domain.RoleCreationResult, 4)
		errors := make(chan error, 4)
		for range 4 {
			wg.Go(func() { r, err := apply(actor, binding, c, true); results <- r; errors <- err })
		}
		wg.Wait()
		close(results)
		close(errors)
		for err := range errors {
			require.NoError(t, err)
		}
		created := 0
		for r := range results {
			if !r.Replayed {
				created++
			}
		}
		require.Equal(t, 1, created)
	})
	t.Run("caller rollback owns result", func(t *testing.T) {
		c := command
		c.OperationID, c.Key = "e2000000-0000-4000-8000-000000000086", "platform_drill_rollback"
		tx, err := runtime.Begin(ctx)
		require.NoError(t, err)
		_, prepared := catalog.CreatePlatformRoleInTransaction(ctx, tx, actor, binding, c, permissions, true)
		require.NoError(t, tx.Rollback(ctx))
		require.NoError(t, prepared)
		require.NoError(t, runtime.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.roles WHERE key=$1)
			AND NOT EXISTS(SELECT 1 FROM auth.platform_role_creations WHERE operation_id=$2)`, c.Key, c.OperationID).Scan(&safe))
		require.True(t, safe)
	})
	t.Run("audit failure rolls back role", func(t *testing.T) {
		_, err := admin.Exec(ctx, `ALTER TABLE auth.platform_role_creations ADD CONSTRAINT fail_drill CHECK(false) NOT VALID`)
		require.NoError(t, err)
		c := command
		c.OperationID, c.Key = "e2000000-0000-4000-8000-000000000085", "platform_drill_failed"
		_, rejected := apply(actor, binding, c, true)
		_, err = admin.Exec(ctx, `ALTER TABLE auth.platform_role_creations DROP CONSTRAINT fail_drill`)
		require.NoError(t, err)
		require.ErrorIs(t, rejected, domain.ErrUnavailable)
		require.NoError(t, runtime.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.roles WHERE key=$1)
			AND NOT EXISTS(SELECT 1 FROM auth.platform_role_creations WHERE operation_id=$2)`, c.Key, c.OperationID).Scan(&safe))
		require.True(t, safe)
	})
	for _, sql := range []string{
		`UPDATE auth.platform_role_creations SET actor_id=actor_id`,
		`DELETE FROM auth.platform_role_creations`,
		`TRUNCATE auth.platform_role_creations`,
		`INSERT INTO auth.platform_role_creations(created_at) VALUES(clock_timestamp())`,
	} {
		_, err := runtime.Exec(ctx, sql)
		require.Error(t, err)
	}
}
