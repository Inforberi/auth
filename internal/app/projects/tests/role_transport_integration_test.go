package projects_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

func roleTransportDrill(t *testing.T, admin *pgx.Conn, managed *catalog.Repository, actor operatordomain.Principal, base domain.RoleCreation,
	registry *projectruntime.Registry, key projectruntime.Key, reader *runtimepostgres.RuntimeCredentialReader, ca *x509.CertPool, permissions settings.Catalog,
) {
	t.Helper()
	ctx := t.Context()
	rootConfig := admin.Config().Copy()
	rootConfig.Database = "authp_" + strings.ReplaceAll(string(base.ProjectID), "-", "")
	projectAdmin, err := pgx.ConnectConfig(ctx, rootConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, projectAdmin.Close(ctx)) }()
	t.Run("backend terminated before write", func(t *testing.T) {
		ctx := t.Context()
		command := base
		command.OperationID, command.Key = "f2000000-0000-4000-8000-000000000041", "bridge_fault_before_write"
		_, err := managed.PrepareRoleCreation(ctx, actor, command)
		require.NoError(t, err)
		grant, err := managed.AdmitRoleCreation(ctx, actor, command)
		require.NoError(t, err)
		err = registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
			conn, ok := db.(*pgxpool.Conn)
			require.True(t, ok)
			var terminated bool
			err := projectAdmin.QueryRow(ctx, `SELECT pg_terminate_backend($1,1000)`, conn.Conn().PgConn().PID()).Scan(&terminated)
			require.NoError(t, err)
			require.True(t, terminated)
			_, executionErr := grant.Execute(ctx, db, permissions, true)
			require.Error(t, executionErr)
			require.NotErrorIs(t, executionErr, domain.ErrOperationOutcomeUnknown, "failure occurred before a transaction could start")
			return nil
		})
		require.NoError(t, err)
		var missing bool
		require.NoError(t, projectAdmin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.platform_role_creations WHERE operation_id=$1)
			AND NOT EXISTS(SELECT 1 FROM auth.roles WHERE key=$2)`, command.OperationID, command.Key).Scan(&missing))
		require.True(t, missing)
	})
	t.Run("TCP closed after durable commit before reply", func(t *testing.T) {
		ctx := t.Context()
		command := base
		command.OperationID, command.Key = "f2000000-0000-4000-8000-000000000042", "bridge_fault_wire_commit"
		_, err := managed.PrepareRoleCreation(ctx, actor, command)
		require.NoError(t, err)
		value, err := reader.LoadDatabaseCredential(ctx, key)
		require.NoError(t, err)
		cfg, err := pgx.ParseConfig("postgres://runtime@127.0.0.1:5432/runtime?sslmode=disable&connect_timeout=1")
		require.NoError(t, err)
		cfg.Database, cfg.User, cfg.Password = rootConfig.Database, "authr_"+strings.ReplaceAll(string(base.ProjectID), "-", ""), value.Password()
		cfg.TLSConfig, cfg.Fallbacks = &tls.Config{RootCAs: ca, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, nil
		cfg.RequireAuth = "scram-sha-256"
		gate := &roleReplyGate{entered: make(chan struct{}), closed: make(chan struct{})}
		cfg.AfterNetConnect = func(_ context.Context, _ *pgconn.Config, conn net.Conn) (net.Conn, error) {
			gate.Conn = conn
			return gate, nil
		}
		conn, err := pgx.ConnectConfig(ctx, cfg)
		require.NoError(t, err)
		defer func() { _ = gate.Close() }()
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_ = conn.Close(cleanup)
		}()
		require.NoError(t, schemapostgres.CheckRuntimeConnection(ctx, conn, key.Binding))
		grant, err := managed.AdmitRoleCreation(ctx, actor, command)
		require.NoError(t, err)
		attempt := make(chan error, 1)
		go func() {
			_, err := grant.Execute(ctx, roleWireDatabase{Conn: conn, gate: gate}, permissions, true)
			attempt <- err
		}()
		select {
		case <-gate.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("client did not reach the COMMIT reply gate")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		waitRoleSQL(t, ctx, projectAdmin, `SELECT EXISTS(SELECT 1 FROM auth.platform_role_creations WHERE operation_id=$1)`, command.OperationID)
		require.NoError(t, gate.Close())
		require.ErrorIs(t, <-attempt, domain.ErrOperationOutcomeUnknown)
		_, err = admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.projects.read')`, actor.UserID)
		require.NoError(t, err)
		defer func() {
			_, err := admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.read'`, actor.UserID)
			require.NoError(t, err)
		}()
		recovered, err := managed.ReconcileRoleOutcome(ctx, actor, command.ProjectID, command.OperationID, registry)
		require.NoError(t, err)
		require.True(t, recovered.Committed)
		var exactlyOnce bool
		require.NoError(t, projectAdmin.QueryRow(ctx, `SELECT count(*)=1 FROM auth.roles WHERE key=$1`, command.Key).Scan(&exactlyOnce))
		require.True(t, exactlyOnce)
		var admissions int
		require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, command.OperationID).Scan(&admissions))
		require.Equal(t, 1, admissions, "receipt recovery must not issue another admission")
	})
}
