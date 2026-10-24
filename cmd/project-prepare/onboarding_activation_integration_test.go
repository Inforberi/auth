package main

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	storage "github.com/Inforberi/financial-intelligence/internal/platform/project/storage/postgres"
)

func onboardingActivationDrill(t *testing.T, physical *pgx.Conn, env func(string) string, repo *catalog.PreparationRepository, r domain.PreparationReservation, b credentials.Binding, codec *credentials.Codec, markerBefore string) string {
	t.Helper()
	ctx := t.Context()
	value, err := repo.ReadDatabaseCredential(ctx, r, b, codec)
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(physical.Config().ConnString())
	require.NoError(t, err)
	cfg.ConnConfig.Database, _, err = r.ResourceNames()
	require.NoError(t, err)
	cfg.ConnConfig.Host, cfg.ConnConfig.User, cfg.ConnConfig.Password = "127.0.0.1", "authr_a2000000000040008000000000000001", value.Password()
	cfg.MaxConns, cfg.MinConns = 2, 0
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer runtime.Close()
	open := func() (*storage.Target, *pgx.Conn) {
		config, err := connectionConfig(env("PROVISIONER_STORAGE_URL"))
		require.NoError(t, err)
		conn, err := pgx.ConnectConfig(ctx, config)
		require.NoError(t, err)
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			require.NoError(t, conn.Close(cleanup))
		})
		target, err := storage.New(conn, b.RealmID, b.StorageTarget)
		require.NoError(t, err)
		return target, conn
	}
	check := func(state string, admitted bool) string {
		var actual, xmin string
		var safe bool
		err := physical.QueryRow(ctx, `SELECT s.onboarding_state,s.xmin::text,
			d.datallowconn=$2 AND role.rolcanlogin=$2 AND has_database_privilege(role.oid,d.oid,'CONNECT')=$2
			FROM provisioning.resources s JOIN pg_database d ON d.oid=s.database_oid JOIN pg_roles role ON role.oid=s.runtime_oid
			WHERE s.project_id=$1`, r.ProjectID, state == "open").Scan(&actual, &xmin, &safe)
		require.NoError(t, err)
		require.Equal(t, state, actual)
		require.True(t, safe)
		var catalogFlag bool
		admin, err := pgx.Connect(ctx, env("PROVISIONER_CATALOG_URL"))
		require.NoError(t, err)
		require.NoError(t, admin.QueryRow(ctx, `SELECT onboarding_admitted FROM platform.project_preparations WHERE project_id=$1`, r.ProjectID).Scan(&catalogFlag))
		require.NoError(t, admin.Close(ctx))
		require.Equal(t, admitted, catalogFlag)
		return xmin
	}
	target, conn := open()
	require.NoError(t, target.ActivateOnboarding(ctx, r, b, codec, repo, runtime))
	xmin := check("open", true)
	next := r
	next.Generation++
	_, err = target.Prepare(ctx, next)
	require.ErrorIs(t, err, domain.ErrConflict, "offline prepare must not advance an open journal")
	require.Equal(t, xmin, check("open", true))
	require.NoError(t, runtime.Ping(ctx))
	var markerAfterFaultDrill string
	t.Run("project role transaction", func(t *testing.T) { markerAfterFaultDrill = projectRoleDrill(t, physical, runtime, b, markerBefore) })
	t.Run("platform role admission", func(t *testing.T) { roleAdmissionDrill(t, physical, runtime, env, r, b, codec) })
	other, otherConn := open()
	require.ErrorIs(t, other.CloseOnboarding(ctx, r, b, repo), storage.ErrBusy)
	require.NoError(t, otherConn.Close(ctx))
	require.NoError(t, conn.Close(ctx))
	// Recreate the executor: an open journal survives process/session lifetime, without target rewrites.
	target, conn = open()
	require.NoError(t, target.ActivateOnboarding(ctx, r, b, codec, repo, runtime))
	require.Equal(t, xmin, check("open", true))
	stale := r
	stale.OperationID = "b2000000-0000-4000-8000-000000000099"
	require.ErrorIs(t, target.CloseOnboarding(ctx, stale, b, repo), domain.ErrConflict)
	require.Equal(t, xmin, check("open", true))
	// Hold an actual uncommitted project write. Closing must terminate it, not just prohibit new logins.
	leased, err := runtime.Acquire(ctx)
	require.NoError(t, err)
	defer leased.Release()
	tx, err := leased.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO auth.users(id) VALUES('e2000000-0000-4000-8000-000000000099')`)
	require.NoError(t, err)
	require.NoError(t, target.CloseOnboarding(ctx, r, b, repo))
	require.Error(t, tx.Commit(ctx))
	leased.Release()
	xmin = check("closed", false)
	require.NoError(t, target.CloseOnboarding(ctx, r, b, repo))
	require.Equal(t, xmin, check("closed", false))
	require.Error(t, runtime.Ping(ctx))
	require.NoError(t, conn.Close(ctx))
	wrongCfg := cfg.Copy()
	wrongCfg.ConnConfig.Password = "wrong-fixture-password"
	wrong, err := pgxpool.NewWithConfig(ctx, wrongCfg)
	require.NoError(t, err)
	defer wrong.Close()
	target, conn = open()
	require.Error(t, target.ActivateOnboarding(ctx, r, b, codec, repo, wrong))
	check("closed", false)
	require.NoError(t, conn.Close(ctx))
	onboardingActivationFailures(t, physical, env, repo, r, b, codec, runtime, open, check)
	return markerAfterFaultDrill
}
