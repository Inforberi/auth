package projects_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	roleshttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/transport/http"
)

func roleDirectoryHTTPDrill(t *testing.T, admin *pgx.Conn, actor operatordomain.Principal, base domain.RoleCreation, binding credentials.Binding,
	role roleshttp.PlatformRoleResponse, call roleHTTPCall, send roleHTTPSend,
) {
	t.Helper()
	ctx := t.Context()
	path := "/api/v1/platform/projects/" + string(base.ProjectID) + "/roles"
	query := fmt.Sprintf("?expectedVersion=%d&expectedGeneration=%d", base.ExpectedVersion, base.ExpectedGeneration)
	detail := path + "/" + string(role.ID) + query
	var before, after int
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions`).Scan(&before))
	var page roleshttp.PlatformRolePageResponse
	require.NoError(t, json.Unmarshal(call(t, "GET", path+query+"&afterKey=bridge_http_edit&limit=1", nil, 200), &page))
	require.Len(t, page.Roles, 1)
	require.Equal(t, role.Key, page.Roles[0].Key)
	require.Equal(t, role.Version, page.Roles[0].Version)
	var current roleshttp.PlatformRoleResponse
	require.NoError(t, json.Unmarshal(call(t, "GET", detail, nil, 200), &current))
	require.Equal(t, role, current)
	call(t, "GET", path+"/f8000000-0000-4000-8000-000000000001"+query, nil, 404)
	call(t, "GET", path+fmt.Sprintf("?expectedVersion=%d&expectedGeneration=%d", base.ExpectedVersion+1, base.ExpectedGeneration), nil, 409)
	call(t, "GET", "/api/v1/platform/projects/f8000000-0000-4000-8000-000000000002/roles"+query, nil, 409)
	call(t, "GET", path+query+"&limit=101", nil, 400)
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions`).Scan(&after))
	require.Equal(t, before, after, "directory reads must not create admissions")

	t.Run("revoke during read discards project data", func(t *testing.T) {
		cfg := admin.Config().Copy()
		var err error
		cfg.Database, _, err = (domain.PreparationReservation{ProjectID: binding.ProjectID, ReservationID: binding.ReservationID}).ResourceNames()
		require.NoError(t, err)
		db, err := pgx.ConnectConfig(ctx, cfg)
		require.NoError(t, err)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			require.NoError(t, db.Close(cleanup))
		}()
		tx, err := db.Begin(ctx)
		require.NoError(t, err)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup) //nolint:gosec // The fixture is read-only except for its temporary lock.
		}()
		_, err = tx.Exec(ctx, `LOCK TABLE auth.roles IN ACCESS EXCLUSIVE MODE`)
		require.NoError(t, err)
		finished := make(chan roleHTTPResult, 1)
		go func() { finished <- send(ctx, "GET", detail, nil) }()
		waitRoleSQL(t, ctx, db, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datid=$1 AND usesysid=$2 AND wait_event_type='Lock')`, binding.DatabaseOID, binding.RuntimeOID)
		_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_access.manage'`, actor.UserID)
		require.NoError(t, err)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_, err := admin.Exec(cleanup, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_access.manage') ON CONFLICT DO NOTHING`, actor.UserID)
			require.NoError(t, err)
		}()
		require.NoError(t, tx.Commit(ctx))
		select {
		case result := <-finished:
			require.NoError(t, result.err)
			require.Equal(t, 403, result.status, "%s", result.body)
			require.NotContains(t, string(result.body), role.Key)
		case <-time.After(4 * time.Second):
			t.Fatal("directory request did not finish")
		}
	})
}
