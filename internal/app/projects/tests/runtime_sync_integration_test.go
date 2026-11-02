package projects_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

func runtimeSyncDrill(t *testing.T, admin *pgx.Conn, reader *runtimepostgres.RuntimeCredentialReader, key projectruntime.Key, target projectruntime.Target) {
	t.Helper()
	ctx := t.Context()
	stale, wrong := key, key
	stale.Version++
	wrong.Binding.DatabaseOID++
	current, err := reader.CurrentRuntimes(ctx, []projectruntime.Key{key, stale, wrong})
	require.NoError(t, err)
	require.Equal(t, []bool{true, false, false}, current)
	foreign := key
	foreign.Binding.RealmID = "c2000000-0000-4000-8000-000000000099"
	_, err = reader.CurrentRuntimes(ctx, []projectruntime.Key{foreign})
	require.ErrorIs(t, err, domain.ErrConflict)
	_, err = reader.CurrentRuntimes(ctx, make([]projectruntime.Key, projectruntime.StateBatchSize+1))
	require.ErrorIs(t, err, domain.ErrInvalidProject)
	// These are two independent resident maps in one process, not a fleet test.
	newRegistry := func() *projectruntime.Registry {
		r, err := projectruntime.New(projectruntime.Config{
			MaxRuntimes: 1, ConnectionsPerProject: 1, ConnectionBudget: 1, MaxAcquiring: 4,
			AcquireTimeout: time.Second, OpenTimeout: time.Second, IdleTimeout: time.Minute,
		}, map[string]projectruntime.Target{key.Binding.StorageTarget: target}, reader, schemapostgres.CheckRuntimeConnection)
		require.NoError(t, err)
		require.NoError(t, r.StartSync(ctx, reader, 10*time.Millisecond, 500*time.Millisecond))
		return r
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `UPDATE platform.projects SET desired_state='enabled',version=$2,generation=$3 WHERE id=$1`, key.Binding.ProjectID, key.Version, key.Generation)
		require.NoError(t, err)
	})
	first, second := newRegistry(), newRegistry()
	defer func() { require.NoError(t, first.Close(ctx)); require.NoError(t, second.Close(ctx)) }()
	pid := func(db projectruntime.Database) uint32 {
		conn, ok := db.(*pgxpool.Conn)
		require.True(t, ok)
		return conn.Conn().PgConn().PID()
	}
	var activePID, idlePID uint32
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	release := sync.OnceFunc(func() { close(finish) })
	defer release()
	go func() {
		done <- first.Use(ctx, key, func(_ context.Context, db projectruntime.Database) error {
			activePID = pid(db)
			close(entered)
			<-finish
			return nil
		})
	}()
	<-entered
	require.NoError(t, second.Use(ctx, key, func(_ context.Context, db projectruntime.Database) error { idlePID = pid(db); return nil }))
	// Simulate a change elsewhere: neither registry receives a local Observe call.
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1,generation=generation+1 WHERE id=$1`, key.Binding.ProjectID)
	require.NoError(t, err)
	waitRoleSQL(t, ctx, admin, `SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)`, idlePID)
	require.Eventually(t, func() bool {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer cancel()
		err := first.Use(bounded, key, func(context.Context, projectruntime.Database) error {
			t.Error("retired snapshot was reissued")
			return nil
		})
		return errors.Is(err, projectruntime.ErrBusy)
	}, time.Second, 5*time.Millisecond, "retired entry waits before acquiring, unlike a merely busy connection")
	var stillActive bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)`, activePID).Scan(&stillActive))
	require.True(t, stillActive)
	release()
	require.NoError(t, <-done)
	waitRoleSQL(t, ctx, admin, `SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)`, activePID)
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled',version=version+1,generation=generation+1 WHERE id=$1`, key.Binding.ProjectID)
	require.NoError(t, err)
	resumed := key
	resumed.Version, resumed.Generation = key.Version+2, key.Generation+2
	var resumedPIDs []uint32
	for _, r := range []*projectruntime.Registry{first, second} {
		require.ErrorIs(t, r.Use(ctx, key, func(context.Context, projectruntime.Database) error { t.Error("stale key was loaded"); return nil }), projectruntime.ErrUnavailable)
		require.NoError(t, r.Use(ctx, resumed, func(_ context.Context, db projectruntime.Database) error {
			resumedPIDs = append(resumedPIDs, pid(db))
			return nil
		}))
	}
	// Reader failure must retire reusable entries too, not silently extend them.
	_, err = admin.Exec(ctx, `REVOKE SELECT ON platform.projects FROM auth_platform_runtime_reader_test`)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `GRANT SELECT ON platform.projects TO auth_platform_runtime_reader_test`)
		require.NoError(t, err)
	}()
	_, err = reader.CurrentRuntimes(ctx, []projectruntime.Key{resumed})
	require.Error(t, err)
	// Polling notices the missing read grant and closes both independently cached pools.
	waitRoleSQL(t, ctx, admin, `SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid IN ($1,$2))`, resumedPIDs[0], resumedPIDs[1])
	_, err = admin.Exec(ctx, `GRANT SELECT ON platform.projects TO auth_platform_runtime_reader_test`)
	require.NoError(t, err)
	for _, r := range []*projectruntime.Registry{first, second} {
		require.NoError(t, r.Use(ctx, resumed, func(context.Context, projectruntime.Database) error { return nil }))
	}
}
