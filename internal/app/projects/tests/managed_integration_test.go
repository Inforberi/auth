package projects_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/database/postgres"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	preparationcli "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/transport/cli"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
	preparationapp "github.com/Inforberi/financial-intelligence/internal/app/projects/preparation"
)

func managedPreparationDrill(t *testing.T, physical *pgx.Conn, env func(string) string, passwordArgs []string, repo *preparationpostgres.PreparationRepository,
	r domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec, inspect func(func(*pgx.Conn)),
) {
	t.Helper()
	ctx := t.Context()
	proof, err := repo.ReadSetupProof(ctx, r, binding, codec)
	require.NoError(t, err)
	inspect(func(db *pgx.Conn) {
		var empty bool
		require.NoError(t, db.QueryRow(ctx, `SELECT NOT configuration_prepared AND NOT smtp_prepared
			AND NOT EXISTS(SELECT 1 FROM auth.auth_settings) AND NOT EXISTS(SELECT 1 FROM auth.initial_setup)
			AND NOT EXISTS(SELECT 1 FROM auth.users) AND NOT EXISTS(SELECT 1 FROM auth.roles) FROM project_meta.identity`).Scan(&empty))
		require.True(t, empty, "managed fixture must not replace existing configuration")
	})
	args := append(append([]string{}, passwordArgs...), "-managed")
	var response bytes.Buffer
	require.NoError(t, preparationcli.Run(ctx, args, env, &response, io.Discard))
	require.Contains(t, response.String(), `"stage":"managed_configuration_prepared"`)
	require.NotContains(t, response.String(), proof.Digest())
	t.Cleanup(func() {
		// Restore only this isolated pre-onboarding fixture for the legacy regression below.
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer stop()
		inspect(func(db *pgx.Conn) {
			var own bool
			require.NoError(t, db.QueryRow(cleanup, `SELECT configuration_prepared AND setup_operator_hash=$1 FROM project_meta.identity`, proof.Digest()).Scan(&own))
			require.True(t, own)
			_, err := db.Exec(cleanup, `DELETE FROM auth.initial_setup; DELETE FROM auth.auth_settings;
				UPDATE project_meta.identity SET configuration_prepared=false,setup_operator_hash=NULL WHERE singleton`)
			require.NoError(t, err)
		})
	})
	var policyXmin, markerXmin, setupXmin string
	inspect(func(db *pgx.Conn) {
		var safe bool
		require.NoError(t, db.QueryRow(ctx, `SELECT m.configuration_prepared AND NOT m.smtp_prepared AND m.setup_operator_hash=$1
			AND p.version=1 AND NOT(p.password_enabled OR p.email_otp_enabled OR p.google_enabled OR p.telegram_enabled
			OR p.registration_enabled OR p.google_registration_enabled OR p.telegram_registration_enabled
			OR p.token_session_exchange_enabled OR p.token_native_enabled) AND p.password_email_verification='disabled'
			AND s.initialized_at IS NULL AND s.administrator_id IS NULL AND s.operator_hash=$1 AND s.payload IS NULL
			AND NOT EXISTS(SELECT 1 FROM auth.smtp_settings) AND NOT EXISTS(SELECT 1 FROM auth.users) AND NOT EXISTS(SELECT 1 FROM auth.roles),
			p.xmin::text,m.xmin::text,s.xmin::text FROM project_meta.identity m CROSS JOIN auth.auth_settings p CROSS JOIN auth.initial_setup s`, proof.Digest()).Scan(&safe, &policyXmin, &markerXmin, &setupXmin))
		require.True(t, safe)
	})
	require.NoError(t, preparationcli.Run(ctx, args, env, io.Discard, io.Discard))
	legacy := append(append([]string{}, passwordArgs...), "-onboarding")
	require.ErrorIs(t, preparationcli.Run(ctx, legacy, env, io.Discard, io.Discard), domain.ErrConflict)
	inspect(func(db *pgx.Conn) {
		var same bool
		require.NoError(t, db.QueryRow(ctx, `SELECT p.xmin::text=$1 AND m.xmin::text=$2 AND s.xmin::text=$3
			FROM project_meta.identity m CROSS JOIN auth.auth_settings p CROSS JOIN auth.initial_setup s`, policyXmin, markerXmin, setupXmin).Scan(&same))
		require.True(t, same, "replay or a different profile must not rewrite the managed configuration")
	})
	managedActivationDrill(t, physical, env, repo, r, binding, codec, proof)
}

func managedActivationDrill(t *testing.T, physical *pgx.Conn, env func(string) string, repo *preparationpostgres.PreparationRepository,
	r domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec, proof credentials.SetupProof,
) {
	t.Helper()
	ctx := t.Context()
	cfg, err := preparationapp.ConnectionConfig(env("PROVISIONER_STORAGE_URL"))
	require.NoError(t, err)
	control, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, control.Close(ctx)) }()
	target, err := storage.New(control, binding.RealmID, binding.StorageTarget)
	require.NoError(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		require.NoError(t, target.CloseOnboarding(cleanup, r, binding, repo))
	}()
	value, err := repo.ReadDatabaseCredential(ctx, r, binding, codec)
	require.NoError(t, err)
	poolCfg, err := pgxpool.ParseConfig(physical.Config().ConnString())
	require.NoError(t, err)
	poolCfg.ConnConfig = physical.Config().Copy()
	poolCfg.ConnConfig.Database, _, err = r.ResourceNames()
	require.NoError(t, err)
	poolCfg.ConnConfig.Host, poolCfg.ConnConfig.User, poolCfg.ConnConfig.Password = "127.0.0.1", "authr_"+strings.ReplaceAll(string(r.ProjectID), "-", ""), value.Password()
	cert, err := os.ReadFile(os.Getenv("AUTH_STORAGE_TEST_TLS_CA"))
	require.NoError(t, err, "managed runtime drill requires the explicit disposable TLS CA")
	ca := x509.NewCertPool()
	require.True(t, ca.AppendCertsFromPEM(cert))
	poolCfg.ConnConfig.TLSConfig = &tls.Config{RootCAs: ca, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	poolCfg.ConnConfig.Fallbacks = nil
	poolCfg.MaxConns, poolCfg.MinConns, poolCfg.MinIdleConns = 1, 0, 0
	wrongCfg := poolCfg.Copy()
	wrongCfg.ConnConfig.Password = "wrong-managed-fixture-password"
	wrong, err := pgxpool.NewWithConfig(ctx, wrongCfg)
	require.NoError(t, err)
	defer wrong.Close()
	require.Error(t, target.ActivateManagedRuntime(ctx, r, binding, codec, repo, wrong))
	var sealed bool
	require.NoError(t, physical.QueryRow(ctx, `SELECT NOT d.datallowconn AND NOT role.rolcanlogin AND NOT has_database_privilege(role.oid,d.oid,'CONNECT')
		FROM pg_database d JOIN pg_roles role ON role.rolname=$2 WHERE d.oid=$1`, binding.DatabaseOID, poolCfg.ConnConfig.User).Scan(&sealed))
	require.True(t, sealed, "failed authentication must close the project")
	runtime, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	defer runtime.Close()
	require.NoError(t, target.ActivateManagedRuntime(ctx, r, binding, codec, repo, runtime))
	var journalXmin string
	require.NoError(t, physical.QueryRow(ctx, `SELECT xmin::text FROM provisioning.resources WHERE project_id=$1`, r.ProjectID).Scan(&journalXmin))
	require.NoError(t, target.ActivateManagedRuntime(ctx, r, binding, codec, repo, runtime))
	var unchanged bool
	require.NoError(t, physical.QueryRow(ctx, `SELECT xmin::text=$2 FROM provisioning.resources WHERE project_id=$1`, r.ProjectID, journalXmin).Scan(&unchanged))
	require.True(t, unchanged, "managed activation replay must not rewrite the journal")
	require.NoError(t, schemapostgres.CheckManagedRuntime(ctx, runtime, proof))
	_, err = runtime.Exec(ctx, `UPDATE auth.initial_setup SET attempts=1 WHERE singleton`)
	require.NoError(t, err)
	require.ErrorIs(t, schemapostgres.CheckManagedRuntime(ctx, runtime, proof), domain.ErrConflict, "managed readiness must reject an active first-admin flow")
	_, err = runtime.Exec(ctx, `UPDATE auth.initial_setup SET attempts=0 WHERE singleton`)
	require.NoError(t, err)
	require.ErrorIs(t, schemapostgres.CheckOnboardingRuntime(ctx, runtime, proof), domain.ErrConflict)
	require.ErrorIs(t, repo.PermitOnboarding(ctx, r, binding, codec, runtime), domain.ErrConflict)
	var closed bool
	require.NoError(t, runtime.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.users) AND NOT EXISTS(SELECT 1 FROM auth.roles)
		AND NOT EXISTS(SELECT 1 FROM auth.smtp_settings)`).Scan(&closed))
	require.True(t, closed)
	catalogCfg, err := preparationapp.ConnectionConfig(env("PROVISIONER_CATALOG_URL"))
	require.NoError(t, err)
	catalogDB, err := pgx.ConnectConfig(ctx, catalogCfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, catalogDB.Close(ctx)) }()
	require.NoError(t, catalogDB.QueryRow(ctx, `SELECT NOT prep.onboarding_admitted AND p.phase='provisioning'
		AND p.database_name IS NULL AND p.credential_ref IS NULL FROM platform.projects p
		JOIN platform.project_preparations prep ON prep.project_id=p.id WHERE p.id=$1`, r.ProjectID).Scan(&closed))
	require.True(t, closed, "SQL activation must not publish ready or admit setup HTTP")
}
