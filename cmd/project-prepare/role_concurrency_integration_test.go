package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

type roleAttempt struct {
	result domain.RoleCreationResult
	err    error
}

func roleRaceCommand(base domain.RoleCreation, number int, key string) domain.RoleCreation {
	base.OperationID = domain.ID(fmt.Sprintf("f3000000-0000-4000-8000-%012d", number))
	base.Key = "bridge_race_" + key
	return base
}

func roleConcurrencyDrill(t *testing.T, admin, projectAdmin *pgx.Conn, project *pgxpool.Pool,
	managed *catalog.Repository, actor operatordomain.Principal, base domain.RoleCreation, permissions settings.Catalog,
) {
	t.Helper()
	prepare := func(t *testing.T, ctx context.Context, command domain.RoleCreation) *catalog.AdmittedRoleCreation {
		t.Helper()
		_, err := managed.PrepareRoleCreation(ctx, actor, command)
		require.NoError(t, err)
		grant, err := managed.AdmitRoleCreation(ctx, actor, command)
		require.NoError(t, err)
		return grant
	}
	t.Run("one admission used concurrently", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		command := roleRaceCommand(base, 1, "single_admission")
		grant := prepare(t, ctx, command)
		start, attempts := make(chan struct{}), make(chan roleAttempt, 4)
		for range 4 {
			go func() {
				<-start
				result, err := grant.Execute(ctx, project, permissions, true)
				attempts <- roleAttempt{result, err}
			}()
		}
		close(start)
		created := 0
		for range 4 {
			attempt := <-attempts
			if attempt.err == nil {
				created++
				require.False(t, attempt.result.Replayed)
				require.True(t, attempt.result.CatalogRecorded)
			} else {
				require.ErrorIs(t, attempt.err, domain.ErrConflict)
			}
		}
		require.Equal(t, 1, created)
		var receipts int
		require.NoError(t, projectAdmin.QueryRow(ctx, `SELECT count(*) FROM auth.platform_role_creations WHERE operation_id=$1`, command.OperationID).Scan(&receipts))
		require.Equal(t, 1, receipts)
	})
	t.Run("different operations compete for one role key", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		left := roleRaceCommand(base, 2, "unique_key")
		right := roleRaceCommand(base, 3, "unique_key")
		left.Name, right.Name = "First request", "Second request"
		left.Permissions, right.Permissions = []accessdomain.PermissionKey{settings.UsersRead}, []accessdomain.PermissionKey{settings.RolesManage}
		grants := []*catalog.AdmittedRoleCreation{prepare(t, ctx, left), prepare(t, ctx, right)}
		start, attempts := make(chan struct{}), make(chan roleAttempt, 2)
		for _, grant := range grants {
			go func() {
				<-start
				result, err := grant.Execute(ctx, project, permissions, true)
				attempts <- roleAttempt{result, err}
			}()
		}
		close(start)
		created := 0
		for range 2 {
			attempt := <-attempts
			if attempt.err == nil {
				created++
				require.True(t, attempt.result.CatalogRecorded)
				if attempt.result.Role.Name == left.Name {
					require.Equal(t, left.Permissions, attempt.result.Role.Permissions)
				} else {
					require.Equal(t, right.Name, attempt.result.Role.Name)
					require.Equal(t, right.Permissions, attempt.result.Role.Permissions)
				}
			} else {
				require.ErrorIs(t, attempt.err, accessdomain.ErrConflict)
			}
		}
		require.Equal(t, 1, created)
		var receipts, outcomes int
		require.NoError(t, projectAdmin.QueryRow(ctx, `SELECT count(*) FROM auth.platform_role_creations WHERE operation_id IN ($1,$2)`, left.OperationID, right.OperationID).Scan(&receipts))
		require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_outcomes WHERE operation_id IN ($1,$2)`, left.OperationID, right.OperationID).Scan(&outcomes))
		require.Equal(t, 1, receipts)
		require.Equal(t, 1, outcomes)
	})
	for i, commit := range []bool{true, false} {
		t.Run(fmt.Sprintf("local role writer commits=%t", commit), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := roleRaceCommand(base, 4+i, fmt.Sprintf("local_%d", i))
			grant := prepare(t, ctx, command)
			blocker, err := projectAdmin.Begin(ctx)
			require.NoError(t, err)
			defer func() {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				defer stop()
				_ = blocker.Rollback(cleanup)
			}()
			require.NoError(t, accesspostgres.LockAccessChanges(ctx, blocker))
			_, err = accesspostgres.InsertRoleInTransaction(ctx, blocker, accessdomain.Role{Key: command.Key, Name: "Local administrator"})
			require.NoError(t, err)
			attempt := make(chan error, 1)
			go func() { _, e := grant.Execute(ctx, project, permissions, true); attempt <- e }()
			waitRoleSQL(t, ctx, blocker, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
				AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock(734013981)%')`)
			if commit {
				require.NoError(t, blocker.Commit(ctx))
				require.ErrorIs(t, <-attempt, accessdomain.ErrConflict)
			} else {
				require.NoError(t, blocker.Rollback(ctx))
				require.NoError(t, <-attempt)
			}
			var receipts int
			require.NoError(t, projectAdmin.QueryRow(ctx, `SELECT count(*) FROM auth.platform_role_creations WHERE operation_id=$1`, command.OperationID).Scan(&receipts))
			if commit {
				require.Zero(t, receipts)
			} else {
				require.Equal(t, 1, receipts)
			}
		})
	}
}
