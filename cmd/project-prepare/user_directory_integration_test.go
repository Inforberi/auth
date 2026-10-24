package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

func userDirectoryHTTPDrill(t *testing.T, admin, project *pgx.Conn, actor operatordomain.Principal, base domain.RoleCreation,
	role projecthttp.PlatformRoleResponse, call roleHTTPCall, send roleHTTPSend,
) {
	t.Helper()
	ctx := t.Context()
	path := "/api/v1/platform/projects/" + string(base.ProjectID) + "/users"
	query := fmt.Sprintf("?expectedVersion=%d&expectedGeneration=%d", base.ExpectedVersion, base.ExpectedGeneration)
	detail := path + "/" + string(assignmentActive) + query
	var granted bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_users.manage')`, actor.UserID).Scan(&granted))
	require.False(t, granted, "fixture must not replace existing user-management authority")
	call(t, "GET", path+query, nil, 403)
	_, err := admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_users.manage')`, actor.UserID)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_users.manage'`, actor.UserID)
		require.NoError(t, err)
	}()
	var first, second accounthttp.UserPageResponse
	require.NoError(t, json.Unmarshal(call(t, "GET", path+query+"&limit=1", nil, 200), &first))
	require.Len(t, first.Users, 1)
	require.NotEmpty(t, first.NextCursor)
	require.NoError(t, json.Unmarshal(call(t, "GET", path+query+"&limit=1&before="+url.QueryEscape(first.NextCursor), nil, 200), &second))
	require.Len(t, second.Users, 1)
	require.NotEqual(t, first.Users[0].ID, second.Users[0].ID)
	var pending, filtered accounthttp.UserPageResponse
	require.NoError(t, json.Unmarshal(call(t, "GET", path+query+"&status=pending", nil, 200), &pending))
	require.Len(t, pending.Users, 1)
	require.Equal(t, assignmentPending, pending.Users[0].ID)
	require.NoError(t, json.Unmarshal(call(t, "GET", path+query+"&email="+url.QueryEscape("ASSIGNMENT-ADMIN@example.test"), nil, 200), &filtered))
	require.Len(t, filtered.Users, 1)
	require.Equal(t, assignmentAdmin, filtered.Users[0].ID)
	var user accounthttp.UserDetailResponse
	body := call(t, "GET", detail, nil, 200)
	require.NoError(t, json.Unmarshal(body, &user))
	require.Equal(t, assignmentActive, user.ID)
	require.EqualValues(t, 2, user.AccessVersion)
	require.Len(t, user.Roles, 1)
	require.Equal(t, role.ID, user.Roles[0].ID)
	require.Equal(t, role.Version, user.Roles[0].Version)
	require.NotContains(t, string(body), "password_hash")
	require.NotContains(t, string(body), "secret")
	call(t, "GET", path+"/f9000000-0000-4000-8000-000000000099"+query, nil, 404)
	call(t, "GET", path+query+"&limit=101", nil, 400)
	call(t, "GET", path+query+"&before=forged", nil, 400)
	call(t, "GET", path+fmt.Sprintf("?expectedVersion=%d&expectedGeneration=%d", base.ExpectedVersion+1, base.ExpectedGeneration), nil, 409)

	t.Run("both permissions required for assignment detail", func(t *testing.T) {
		_, err := admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_access.manage'`, actor.UserID)
		require.NoError(t, err)
		defer restoreDirectoryPermission(t, ctx, admin, actor, operatordomain.AccessManage)
		call(t, "GET", path+query, nil, 200)
		call(t, "GET", detail, nil, 403)
	})
	t.Run("revoked during read discards PII", func(t *testing.T) {
		tx, err := project.Begin(ctx)
		require.NoError(t, err)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup) //nolint:gosec // Only the fixture's temporary table lock is held.
		}()
		_, err = tx.Exec(ctx, `LOCK TABLE auth.users IN ACCESS EXCLUSIVE MODE`)
		require.NoError(t, err)
		finished := make(chan roleHTTPResult, 1)
		go func() { finished <- send(ctx, "GET", detail, nil) }()
		var database uint32
		require.NoError(t, project.QueryRow(ctx, `SELECT oid FROM pg_database WHERE datname=current_database()`).Scan(&database))
		waitRoleSQL(t, ctx, project, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datid=$1 AND pid<>pg_backend_pid() AND wait_event_type='Lock')`, database)
		_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_users.manage'`, actor.UserID)
		require.NoError(t, err)
		defer restoreDirectoryPermission(t, ctx, admin, actor, operatordomain.UsersManage)
		require.NoError(t, tx.Commit(ctx))
		select {
		case result := <-finished:
			require.NoError(t, result.err)
			require.Equal(t, 403, result.status, "%s", result.body)
			require.NotContains(t, string(result.body), string(assignmentActive))
		case <-time.After(4 * time.Second):
			t.Fatal("user directory request did not finish")
		}
	})
	t.Run("retained deleted user is not restored or listed", func(t *testing.T) {
		const deleted accountdomain.UserID = "f9000000-0000-4000-8000-000000000001"
		_, err := project.Exec(ctx, `INSERT INTO auth.users(id,status,deleted_at) VALUES($1,'blocked',clock_timestamp())`, deleted)
		require.NoError(t, err)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_, err := project.Exec(cleanup, `DELETE FROM auth.users WHERE id=$1`, deleted)
			require.NoError(t, err)
		}()
		var retained accounthttp.UserDetailResponse
		require.NoError(t, json.Unmarshal(call(t, "GET", path+"/"+string(deleted)+query, nil, 200), &retained))
		require.NotNil(t, retained.DeletedAt)
		var page accounthttp.UserPageResponse
		require.NoError(t, json.Unmarshal(call(t, "GET", path+query, nil, 200), &page))
		for _, candidate := range page.Users {
			require.NotEqual(t, deleted, candidate.ID)
		}
	})
}

func restoreDirectoryPermission(t *testing.T, ctx context.Context, db *pgx.Conn, actor operatordomain.Principal, permission operatordomain.Permission) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	_, err := db.Exec(cleanup, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, actor.UserID, permission)
	require.NoError(t, err)
}
