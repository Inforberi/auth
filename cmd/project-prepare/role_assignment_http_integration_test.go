package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

type (
	roleHTTPCall func(*testing.T, string, string, any, int) []byte
	roleHTTPSend func(context.Context, string, string, any) roleHTTPResult
)

func roleAssignmentHTTPDrill(t *testing.T, catalog *pgx.Conn, actor operatordomain.Principal, base domain.RoleCreation, binding credentials.Binding,
	role projecthttp.PlatformRoleResponse, call roleHTTPCall, send roleHTTPSend,
) {
	t.Helper()
	ctx := t.Context()
	fixture := newAssignmentFixture(t, catalog, binding)
	db := fixture.db
	path := func(user accountdomain.UserID, id accessdomain.RoleID, action domain.RoleAction) string {
		return fmt.Sprintf("/api/v1/platform/projects/%s/users/%s/roles/%s/%s", base.ProjectID, user, id, action)
	}
	input := func(number, version int64) projecthttp.PlatformAssignmentRequest {
		return projecthttp.PlatformAssignmentRequest{
			OperationID: domain.ID(fmt.Sprintf("f7000000-0000-4000-8000-%012d", number)), ExpectedVersion: base.ExpectedVersion, ExpectedGeneration: base.ExpectedGeneration, ExpectedRoleVersion: role.Version, ExpectedAccessVersion: version, Reason: "Assignment HTTP fixture",
		}
	}
	apply := func(t *testing.T, user accountdomain.UserID, id accessdomain.RoleID, action domain.RoleAction, command projecthttp.PlatformAssignmentRequest, status int) projecthttp.PlatformAssignmentResponse {
		t.Helper()
		data := call(t, "POST", path(user, id, action), command, status)
		var response projecthttp.PlatformAssignmentResponse
		if status < 300 {
			require.NoError(t, json.Unmarshal(data, &response))
			if status == 200 {
				require.NotNil(t, response.Changed)
				require.NotNil(t, response.Role)
				require.Equal(t, "committed", response.Status)
			}
		}
		return response
	}
	state := func(t *testing.T, user accountdomain.UserID, access, auth int64, assigned bool) {
		t.Helper()
		var actualAccess, actualAuth int64
		var found bool
		require.NoError(t, db.QueryRow(t.Context(), `SELECT access_version,auth_version,EXISTS(SELECT 1 FROM auth.user_roles WHERE user_id=$1 AND role_id=$2) FROM auth.users WHERE id=$1`, user, role.ID).Scan(&actualAccess, &actualAuth, &found))
		require.Equal(t, access, actualAccess)
		require.Equal(t, auth, actualAuth)
		require.Equal(t, assigned, found)
	}
	t.Run("grant replay and no-op", func(t *testing.T) {
		first := apply(t, assignmentActive, role.ID, domain.RoleGrant, input(1, 1), 200)
		require.True(t, *first.Changed)
		require.False(t, first.Replayed)
		require.True(t, first.CatalogRecorded)
		state(t, assignmentActive, 2, 2, true)
		t.Run("platform user directory", func(t *testing.T) {
			userDirectoryHTTPDrill(t, catalog, db, actor, base, role, call, send)
		})
		replay := apply(t, assignmentActive, role.ID, domain.RoleGrant, input(1, 1), 200)
		require.True(t, replay.Replayed)
		require.Equal(t, first.AccessVersion, replay.AccessVersion)
		state(t, assignmentActive, 2, 2, true)
		var live bool
		require.NoError(t, db.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version WHERE s.token_hash=$1)`, strings.Repeat("a", 64)).Scan(&live))
		require.False(t, live, "grant must invalidate the pre-grant active session")
		var xmin string
		require.NoError(t, db.QueryRow(t.Context(), `SELECT xmin::text FROM auth.users WHERE id=$1`, assignmentActive).Scan(&xmin))
		noop := apply(t, assignmentActive, role.ID, domain.RoleGrant, input(2, 2), 200)
		require.False(t, *noop.Changed)
		var unchanged bool
		require.NoError(t, db.QueryRow(t.Context(), `SELECT xmin::text=$2 FROM auth.users WHERE id=$1`, assignmentActive, xmin).Scan(&unchanged))
		require.True(t, unchanged)
		apply(t, assignmentActive, role.ID, domain.RoleRevoke, input(1, 1), 409)
		revoked := apply(t, assignmentActive, role.ID, domain.RoleRevoke, input(3, 2), 200)
		require.True(t, *revoked.Changed)
		state(t, assignmentActive, 3, 2, false)
		noop = apply(t, assignmentActive, role.ID, domain.RoleRevoke, input(4, 3), 200)
		require.False(t, *noop.Changed)
		state(t, assignmentActive, 3, 2, false)
	})
	t.Run("target system and capability bounds", func(t *testing.T) {
		reused := input(40, 3)
		reused.OperationID = "f4000000-0000-4000-8000-000000000001"
		apply(t, assignmentActive, role.ID, domain.RoleGrant, reused, 409)
		apply(t, assignmentActive, fixture.system, domain.RoleGrant, input(5, 3), 403)
		apply(t, assignmentAdmin, fixture.system, domain.RoleRevoke, input(6, 1), 403)
		tx, err := db.Begin(t.Context())
		require.NoError(t, err)
		require.NoError(t, accesspostgres.LockAccessChanges(t.Context(), tx))
		require.NoError(t, accesspostgres.RequireUsableAdministrator(t.Context(), tx))
		require.NoError(t, tx.Rollback(t.Context()))
		apply(t, assignmentActive, fixture.mfa, domain.RoleGrant, input(7, 3), 409)
		apply(t, assignmentActive, "f7000000-0000-4000-8000-000000000099", domain.RoleGrant, input(8, 3), 404)
		apply(t, "f7000000-0000-4000-8000-000000000099", role.ID, domain.RoleGrant, input(9, 1), 409)
		apply(t, assignmentCapped, role.ID, domain.RoleGrant, input(10, 1), 409)
		noop := apply(t, assignmentCapped, fixture.capped, domain.RoleGrant, input(11, 1), 200)
		require.False(t, *noop.Changed)
		pending := apply(t, assignmentPending, role.ID, domain.RoleGrant, input(12, 1), 200)
		require.True(t, *pending.Changed)
		state(t, assignmentPending, 2, 1, true)
		apply(t, assignmentPending, role.ID, domain.RoleRevoke, input(13, 2), 200)
		_, err = db.Exec(t.Context(), `UPDATE auth.users SET status='blocked' WHERE id=$1`, assignmentActive)
		require.NoError(t, err)
		apply(t, assignmentActive, role.ID, domain.RoleGrant, input(14, 3), 409)
		apply(t, assignmentActive, role.ID, domain.RoleRevoke, input(15, 3), 200)
		_, err = db.Exec(t.Context(), `UPDATE auth.users SET status='active' WHERE id=$1`, assignmentActive)
		require.NoError(t, err)
	})
	t.Run("receipt failure rolls back binding and versions", func(t *testing.T) {
		_, err := db.Exec(ctx, `ALTER TABLE auth.platform_role_assignments ADD CONSTRAINT reject_assignment_fixture CHECK(false) NOT VALID`)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(ctx, `ALTER TABLE auth.platform_role_assignments DROP CONSTRAINT reject_assignment_fixture`)
			require.NoError(t, err)
		}()
		apply(t, assignmentActive, role.ID, domain.RoleGrant, input(16, 3), 503)
		state(t, assignmentActive, 3, 2, false)
	})
	t.Run("parallel replay and conflicting versions", func(t *testing.T) {
		start, finished := make(chan struct{}), make(chan roleHTTPResult, 4)
		for range 4 {
			go func() {
				<-start
				finished <- send(t.Context(), "POST", path(assignmentActive, role.ID, domain.RoleGrant), input(20, 3))
			}()
		}
		close(start)
		created := 0
		for range 4 {
			r := <-finished
			require.NoError(t, r.err)
			require.Equal(t, 200, r.status, "%s", r.body)
			var result projecthttp.PlatformAssignmentResponse
			require.NoError(t, json.Unmarshal(r.body, &result))
			if !result.Replayed {
				created++
			}
		}
		require.Equal(t, 1, created)
		state(t, assignmentActive, 4, 3, true)
		start = make(chan struct{})
		finished = make(chan roleHTTPResult, 2)
		for i := range 2 {
			go func() {
				<-start
				finished <- send(t.Context(), "POST", path(assignmentActive, role.ID, domain.RoleRevoke), input(int64(30+i), 4))
			}()
		}
		close(start)
		success, conflict := 0, 0
		for range 2 {
			r := <-finished
			require.NoError(t, r.err)
			switch r.status {
			case 200:
				success++
			case 409:
				conflict++
			default:
				t.Fatalf("unexpected response %d: %s", r.status, r.body)
			}
		}
		require.Equal(t, 1, success)
		require.Equal(t, 1, conflict)
		state(t, assignmentActive, 5, 3, false)
		var receipts int
		require.NoError(t, db.QueryRow(t.Context(), `SELECT count(*) FROM auth.platform_role_assignments WHERE operation_id=$1`, input(20, 3).OperationID).Scan(&receipts))
		require.Equal(t, 1, receipts)
	})
	t.Run("outcome recovery never reapplies assignment", func(t *testing.T) {
		command := input(1, 1)
		location := "/api/v1/platform/projects/" + string(base.ProjectID) + "/role-operations/" + string(command.OperationID)
		var before, after int
		require.NoError(t, catalog.QueryRow(t.Context(), `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, command.OperationID).Scan(&before))
		_, err := catalog.Exec(t.Context(), `DELETE FROM platform.project_role_outcomes WHERE operation_id=$1`, command.OperationID)
		require.NoError(t, err)
		var result projecthttp.RoleOutcomeResponse
		require.NoError(t, json.Unmarshal(call(t, "POST", location+"/reconcile", nil, 200), &result))
		require.True(t, result.Committed)
		require.Equal(t, domain.RoleGrant, result.Action)
		require.Equal(t, assignmentActive, result.UserID)
		require.EqualValues(t, 2, result.AccessVersion)
		state(t, assignmentActive, 5, 3, false)
		require.NoError(t, catalog.QueryRow(t.Context(), `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, command.OperationID).Scan(&after))
		require.Equal(t, before, after)
		_, err = catalog.Exec(t.Context(), `DELETE FROM platform.project_role_outcomes WHERE operation_id=$1`, command.OperationID)
		require.NoError(t, err)
		replay := apply(t, assignmentActive, role.ID, domain.RoleGrant, command, 200)
		require.True(t, replay.Replayed)
		var projectAdmission, catalogAdmission string
		require.NoError(t, db.QueryRow(t.Context(), `SELECT admission_id::text FROM auth.platform_role_assignments WHERE operation_id=$1`, command.OperationID).Scan(&projectAdmission))
		require.NoError(t, catalog.QueryRow(t.Context(), `SELECT admission_id::text FROM platform.project_role_outcomes WHERE operation_id=$1`, command.OperationID).Scan(&catalogAdmission))
		require.Equal(t, projectAdmission, catalogAdmission)
		state(t, assignmentActive, 5, 3, false)
		other := "/api/v1/platform/projects/a2000000-0000-4000-8000-000000000099/role-operations/" + string(command.OperationID)
		call(t, "POST", other+"/reconcile", nil, 404)
	})
	t.Run("local Access and last administrator regression", func(t *testing.T) {
		poolCfg, err := pgxpool.ParseConfig(db.Config().ConnString())
		require.NoError(t, err)
		poolCfg.MaxConns = 1
		poolCfg.MinConns = 0
		poolCfg.ConnConfig = db.Config().Copy()
		poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
		pool, err := pgxpool.NewWithConfig(t.Context(), poolCfg)
		require.NoError(t, err)
		defer pool.Close()
		repo := accesspostgres.NewWithMFA(pool, true)
		principal := accessservice.Principal{UserID: assignmentAdmin, TokenHash: strings.Repeat("b", 64)}
		version, err := repo.ChangeAssignment(t.Context(), accessservice.AssignmentInput{Actor: principal, UserID: assignmentPending, RoleID: role.ID, ExpectedRoleVersion: role.Version, ExpectedAccessVersion: 3, Grant: true})
		require.NoError(t, err)
		require.EqualValues(t, 4, version)
		state(t, assignmentPending, 4, 1, true)
		_, err = repo.ChangeAdministrator(t.Context(), accessservice.AdministratorInput{Actor: principal, UserID: assignmentAdmin, ExpectedRoleVersion: 1, ExpectedAccessVersion: 1, ExpectedAuthVersion: 1, Grant: false})
		require.ErrorIs(t, err, accountdomain.ErrLastAdministrator)
		var audit int
		require.NoError(t, db.QueryRow(t.Context(), `SELECT count(*) FROM auth.access_audit WHERE actor_id=$1 AND target_id=$2`, assignmentAdmin, assignmentPending).Scan(&audit))
		require.Equal(t, 1, audit)
		var fake bool
		require.NoError(t, db.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM auth.users WHERE id=$1)`, actor.UserID).Scan(&fake))
		require.False(t, fake)
	})
	t.Run("concurrent role edit invalidates expected version", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		blocker, err := db.Begin(ctx)
		require.NoError(t, err)
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = blocker.Rollback(cleanup)
		}()
		require.NoError(t, accesspostgres.LockAccessChanges(ctx, blocker))
		_, err = blocker.Exec(ctx, `UPDATE auth.roles SET version=version+1 WHERE id=$1`, role.ID)
		require.NoError(t, err)
		finished := make(chan roleHTTPResult, 1)
		go func() { finished <- send(ctx, "POST", path(assignmentActive, role.ID, domain.RoleGrant), input(50, 5)) }()
		waitRoleSQL(t, ctx, blocker, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock(734013981)%')`)
		require.NoError(t, blocker.Commit(ctx))
		result := <-finished
		require.NoError(t, result.err)
		require.Equal(t, 409, result.status, "%s", result.body)
		state(t, assignmentActive, 5, 3, false)
	})
}
