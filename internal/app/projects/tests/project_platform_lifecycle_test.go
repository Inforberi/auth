package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
)

func TestTwoProjectPlatformLifecycleSQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	f := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	webs, handler := serveRecoveryProjects(t, f)
	platform, operator := serveLifecycleOperator(t, pair, f)
	ctx := t.Context()
	cookies := [2]string{isolationSessionLogin(t, ctx, webs[0]), isolationSessionLogin(t, ctx, webs[1])}
	const me = "/api/v1/auth/me"
	path := "/api/v1/platform/projects/" + string(pair.a.Binding.ProjectID)
	input := projecthttp.ChangeStateRequest{OperationID: "f8c00000-0000-4000-8000-000000000001", ExpectedVersion: pair.a.Version, ExpectedGeneration: pair.a.Generation, Reason: "fixture-suspend"}
	isolationCommand(t, ctx, platform, "POST", path+"/suspend", cookies[0], input, 401, nil)
	response := platform.call(t, ctx, "POST", path+"/suspend", f.origins[0], operator, input)
	require.Equal(t, 403, response.status)
	var suspended projecthttp.TransitionResponse
	isolationCommand(t, ctx, platform, "POST", path+"/suspend", operator, input, 200, &suspended)
	require.Equal(t, projectdomain.Suspended, suspended.DesiredState)
	isolationCommand(t, ctx, webs[0], "GET", me, cookies[0], nil, 404, nil)
	isolationCommand(t, ctx, webs[1], "GET", me, cookies[1], nil, 200, nil)
	var replay projecthttp.TransitionResponse
	isolationCommand(t, ctx, platform, "POST", path+"/suspend", operator, input, 200, &replay)
	require.True(t, replay.Replayed)
	require.Equal(t, suspended.Version, replay.Version)
	resume := projecthttp.ChangeStateRequest{OperationID: "f8c00000-0000-4000-8000-000000000002", ExpectedVersion: suspended.Version, ExpectedGeneration: suspended.Generation, Reason: "fixture-resume"}
	var resumed projecthttp.TransitionResponse
	isolationCommand(t, ctx, platform, "POST", path+"/resume", operator, resume, 200, &resumed)
	require.Equal(t, projectdomain.Enabled, resumed.DesiredState)
	require.Equal(t, pair.a.Version+2, resumed.Version)
	isolationCommand(t, ctx, webs[0], "GET", me, cookies[0], nil, 200, nil)
	isolationCommand(t, ctx, webs[1], "GET", me, cookies[1], nil, 200, nil)
	isolationCommand(t, ctx, platform, "POST", path+"/suspend", operator, input, 200, &replay)
	require.True(t, replay.Replayed)
	isolationCommand(t, ctx, webs[0], "GET", me, cookies[0], nil, 200, nil)
	resume.OperationID = "f8c00000-0000-4000-8000-000000000003"
	isolationCommand(t, ctx, platform, "POST", path+"/suspend", operator, resume, 409, nil)
	resume.ExpectedVersion, resume.ExpectedGeneration = resumed.Version, resumed.Generation
	isolationCommand(t, ctx, platform, "POST", path+"/retry", operator, resume, 409, nil)
	restorePermission := func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_, err := pair.admin.Exec(cleanup, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES('d2000000-0000-4000-8000-000000000001','platform.projects.manage') ON CONFLICT DO NOTHING`)
		require.NoError(t, err)
	}
	t.Cleanup(restorePermission)
	_, err := pair.admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id='d2000000-0000-4000-8000-000000000001' AND permission_key='platform.projects.manage'`)
	require.NoError(t, err)
	isolationCommand(t, ctx, platform, "POST", path+"/suspend", operator, input, 403, nil)
	restorePermission()
	isolationCommand(t, ctx, webs[0], "GET", me, cookies[0], nil, 200, nil)
	var events int
	require.NoError(t, pair.admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_events WHERE project_id=$1 AND actor_kind='operator'`, pair.a.Binding.ProjectID).Scan(&events))
	require.Equal(t, 2, events)
	var version, generation int64
	require.NoError(t, pair.admin.QueryRow(ctx, `SELECT version,generation FROM platform.projects WHERE id=$1`, pair.b.Binding.ProjectID).Scan(&version, &generation))
	require.Equal(t, pair.b.Version, version)
	require.Equal(t, pair.b.Generation, generation)
	// Rebuild HTTP residents over the same registry and persistent SQL sessions, not a process restart.
	webs[0].server.Close()
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	require.NoError(t, handler.Close(closeCtx))
	cancel()
	webs, _ = serveRecoveryProjects(t, f)
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", me, cookies[i], nil, 200, nil)
	}
}
