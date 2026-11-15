package projects_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	preparationcli "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/transport/cli"
)

func checkRequestedProjectOperations(t *testing.T, catalog, storage *pgx.Conn, env func(string) string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	const project = "a2000000-0000-4000-8000-000000000002"
	const owner = "d2000000-0000-4000-8000-000000000001"
	const database = "authp_a2000000000040008000000000000002"
	const prepare = "b2000000-0000-4000-8000-000000000002"
	const withoutAck = "b2000000-0000-4000-8000-000000000003"
	const withAck = "b2000000-0000-4000-8000-000000000004"

	var occupied bool
	require.NoError(t, storage.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)
		OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('autho_a2000000000040008000000000000002','authr_a2000000000040008000000000000002'))`, database).Scan(&occupied))
	require.False(t, occupied, "fixture must not replace existing resources")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer stop()
		_, err := storage.Exec(cleanup, `DROP DATABASE IF EXISTS authp_a2000000000040008000000000000002`)
		require.NoError(t, err)
		_, err = storage.Exec(cleanup, `DELETE FROM provisioning.resources WHERE project_id=$1`, project)
		require.NoError(t, err)
		_, err = storage.Exec(cleanup, `DROP ROLE IF EXISTS authr_a2000000000040008000000000000002;
			DROP ROLE IF EXISTS autho_a2000000000040008000000000000002`)
		require.NoError(t, err)
	})
	_, err := catalog.Exec(ctx, `INSERT INTO platform.projects(id,slug,name,origin,storage_target)
		VALUES($1,'ops-test','Operations test','https://operations.example.test','primary')`, project)
	require.NoError(t, err)
	_, err = catalog.Exec(ctx, `INSERT INTO platform.project_preparation_requests(operation_id,project_id,actor_id,expected_version,expected_generation)
		VALUES($1,$2,$3,1,1)`, prepare, project, owner)
	require.NoError(t, err)
	provisionerEnv := func(key string) string {
		switch key {
		case "PROVISIONER_MASTER_KEY":
			return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{21}, 32))
		case "PROVISIONER_MASTER_KEY_ID":
			return "operations-fixture"
		default:
			return env(key)
		}
	}
	watcher, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- preparationcli.Run(watcher, []string{"-watch"}, provisionerEnv, io.Discard, io.Discard, runPreparationCommand)
	}()
	defer func() {
		stop()
		require.NoError(t, <-done)
	}()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		var stage, phase string
		require.NoError(c, catalog.QueryRow(ctx, `SELECT q.stage,p.phase FROM platform.project_preparation_requests q
			JOIN platform.projects p ON p.id=q.project_id WHERE q.operation_id=$1`, prepare).Scan(&stage, &phase))
		require.Equal(c, "ready", stage)
		require.Equal(c, "ready", phase)
	}, 20*time.Second, 100*time.Millisecond)

	projectConfig := storage.Config().Copy()
	projectConfig.Database = database
	projectDB, err := pgx.ConnectConfig(ctx, projectConfig)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, projectDB.Close(context.WithoutCancel(ctx))) })
	_, err = projectDB.Exec(ctx, `INSERT INTO auth.users(id) VALUES('e2000000-0000-4000-8000-000000000002')`)
	require.NoError(t, err)
	require.NoError(t, projectDB.Close(ctx))
	_, err = catalog.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1,generation=generation+1 WHERE id=$1`, project)
	require.NoError(t, err)
	waitForDeletionStage := func(operation, expected string, ack bool) {
		t.Helper()
		_, err := catalog.Exec(ctx, `INSERT INTO platform.project_deletions(operation_id,project_id,actor_id,version,generation,acknowledge_users)
			SELECT $1,id,$2,version,generation,$3 FROM platform.projects WHERE id=$4`, operation, owner, ack, project)
		require.NoError(t, err)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var stage string
			require.NoError(c, catalog.QueryRow(ctx, `SELECT stage FROM platform.project_deletions WHERE operation_id=$1`, operation).Scan(&stage))
			require.Equal(c, expected, stage)
		}, 10*time.Second, 100*time.Millisecond)
	}
	waitForDeletionStage(withoutAck, "users_present", false)
	require.NoError(t, storage.QueryRow(ctx, `SELECT datallowconn FROM pg_database WHERE datname=$1`, database).Scan(&occupied))
	require.True(t, occupied, "unconfirmed loss must preserve the database")
	waitForDeletionStage(withAck, "deleted", true)
	require.NoError(t, storage.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, database).Scan(&occupied))
	require.False(t, occupied)
	require.NoError(t, storage.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname='authp_a2000000000040008000000000000001')`).Scan(&occupied))
	require.True(t, occupied, "deletion must preserve the neighboring project")
}
