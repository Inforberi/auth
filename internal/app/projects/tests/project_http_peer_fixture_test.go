package projects_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	preparationcli "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/transport/cli"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/storage/postgres"
	preparationapp "github.com/Inforberi/financial-intelligence/internal/app/projects/preparation"
)

const httpPeerProject domain.ID = "a2000000-0000-4000-8000-000000000088"

func prepareHTTPPeer(t *testing.T, ctx context.Context, admin *pgx.Conn, env func(string) string, codec *credentials.Codec, ca *x509.CertPool, project, operation domain.ID, origin string) projectruntime.Key {
	t.Helper()
	r := domain.PreparationReservation{ProjectID: project, OperationID: operation, StorageTarget: "primary"}
	suffix := strings.ReplaceAll(string(r.ProjectID), "-", "")
	database, owner, runtime := "authp_"+suffix, "autho_"+suffix, "authr_"+suffix
	physicalCfg := admin.Config().Copy()
	physicalCfg.Database = "auth_storage_test"
	physical, err := pgx.ConnectConfig(ctx, physicalCfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, physical.Close(context.WithoutCancel(ctx))) })
	var occupied bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.projects WHERE id=$1)
 OR EXISTS(SELECT 1 FROM pg_database WHERE datname=$2) OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN($3,$4))`, r.ProjectID, database, owner, runtime).Scan(&occupied))
	require.False(t, occupied, "peer fixture must not replace existing resources")
	require.NoError(t, physical.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM provisioning.resources WHERE project_id=$1)`, r.ProjectID).Scan(&occupied))
	require.False(t, occupied)
	_, err = admin.Exec(ctx, `INSERT INTO platform.projects(id,slug,name,origin,storage_target) VALUES($1,$2,'HTTP peer',$3,'primary')`, r.ProjectID, "http-"+suffix, origin)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, err := physical.Exec(cleanup, `DROP DATABASE IF EXISTS `+pgx.Identifier{database}.Sanitize())
		require.NoError(t, err)
		for _, role := range []string{runtime, owner} {
			_, err := physical.Exec(cleanup, `DROP ROLE IF EXISTS `+pgx.Identifier{role}.Sanitize())
			require.NoError(t, err)
		}
		_, err = physical.Exec(cleanup, `DELETE FROM provisioning.resources WHERE project_id=$1`, r.ProjectID)
		require.NoError(t, err)
		for _, table := range []string{"project_secrets", "project_preparations", "project_events", "project_creations"} {
			_, err := admin.Exec(cleanup, `DELETE FROM platform.`+table+` WHERE project_id=$1`, r.ProjectID)
			require.NoError(t, err)
		}
		_, err = admin.Exec(cleanup, `DELETE FROM platform.projects WHERE id=$1`, r.ProjectID)
		require.NoError(t, err)
	})
	// Commands leave a sealed managed database; publication below is fixture-only, as in the existing runtime drill.
	args := []string{"-project", string(r.ProjectID), "-operation", string(r.OperationID), "-version", "1", "-generation", "1", "-schema", "-secrets", "-password", "-managed"}
	require.NoError(t, preparationcli.Run(ctx, args, env, io.Discard, io.Discard))
	require.NoError(t, admin.QueryRow(ctx, `SELECT prep.reservation_id,p.version,p.generation FROM platform.project_preparations prep JOIN platform.projects p ON p.id=prep.project_id WHERE p.id=$1`, r.ProjectID).Scan(&r.ReservationID, &r.Version, &r.Generation))
	actualDatabase, actualOwner, err := r.ResourceNames()
	require.NoError(t, err)
	require.Equal(t, database, actualDatabase)
	require.Equal(t, owner, actualOwner)
	b := credentials.Binding{RealmID: domain.ID(env("PROVISIONER_REALM_ID")), ProjectID: r.ProjectID, ReservationID: r.ReservationID, StorageTarget: r.StorageTarget, SchemaVersion: 1}
	require.NoError(t, physical.QueryRow(ctx, `SELECT d.oid,d.datdba,r.oid FROM pg_database d CROSS JOIN pg_roles r WHERE d.datname=$1 AND r.rolname=$2`, database, runtime).Scan(&b.DatabaseOID, &b.OwnerOID, &b.RuntimeOID))
	prepCfg, err := pgxpool.ParseConfig(env("PROVISIONER_CATALOG_URL"))
	require.NoError(t, err)
	prepCfg.MaxConns, prepCfg.MinConns = 1, 0
	prepPool, err := pgxpool.NewWithConfig(ctx, prepCfg)
	require.NoError(t, err)
	defer prepPool.Close()
	prep, err := preparationpostgres.NewPreparation(prepPool, b.RealmID, b.StorageTarget)
	require.NoError(t, err)
	value, err := prep.ReadDatabaseCredential(ctx, r, b, codec)
	require.NoError(t, err)
	poolCfg, err := pgxpool.ParseConfig(physical.Config().ConnString())
	require.NoError(t, err)
	poolCfg.ConnConfig.Database, poolCfg.ConnConfig.User, poolCfg.ConnConfig.Password = database, runtime, value.Password()
	poolCfg.ConnConfig.Host = "127.0.0.1"
	poolCfg.ConnConfig.TLSConfig = &tls.Config{RootCAs: ca, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	poolCfg.ConnConfig.Fallbacks = nil
	poolCfg.MaxConns, poolCfg.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	defer pool.Close()
	controlCfg, err := preparationapp.ConnectionConfig(env("PROVISIONER_STORAGE_URL"))
	require.NoError(t, err)
	control, err := pgx.ConnectConfig(ctx, controlCfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, control.Close(context.WithoutCancel(ctx))) }()
	target, err := storage.New(control, b.RealmID, b.StorageTarget)
	require.NoError(t, err)
	require.NoError(t, target.ActivateManagedRuntime(ctx, r, b, codec, prep, pool))
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	err = schemapostgres.CheckRuntimeConnection(ctx, conn.Conn(), b)
	conn.Release()
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET phase='ready',database_name=$2,credential_ref='project:http-peer:db:v1',schema_version=1 WHERE id=$1`, r.ProjectID, database)
	require.NoError(t, err)
	return projectruntime.Key{Binding: b, Version: r.Version, Generation: r.Generation}
}
