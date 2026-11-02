package projects_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	preparationcli "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/transport/cli"
)

func secretsPreparationDrill(t *testing.T, admin, physical *pgx.Conn, env func(string) string, schemaArgs []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	protected := func(key string) string {
		if key == "PROVISIONER_MASTER_KEY" {
			return root
		}
		if key == "PROVISIONER_MASTER_KEY_ID" {
			return "root-1"
		}
		return env(key)
	}
	args := append(append([]string{}, schemaArgs...), "-secrets")
	_, err := admin.Exec(ctx, `ALTER TABLE platform.project_preparations ADD CONSTRAINT fail_secret_flag CHECK(NOT secrets_created)`)
	require.NoError(t, err)
	require.Error(t, preparationcli.Run(ctx, args, protected, io.Discard, io.Discard))
	var clean bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT NOT secrets_created AND NOT EXISTS(SELECT 1 FROM platform.project_secrets)
		FROM platform.project_preparations`).Scan(&clean))
	require.True(t, clean, "ciphertext insert must roll back with the creation flag")
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_preparations DROP CONSTRAINT fail_secret_flag`)
	require.NoError(t, err)
	var reservation domain.PreparationReservation
	var binding credentials.Binding
	reservation.ProjectID = "a2000000-0000-4000-8000-000000000001"
	reservation.OperationID = "b2000000-0000-4000-8000-000000000001"
	reservation.Version, reservation.Generation = 2, 2
	reservation.StorageTarget = "primary"
	require.NoError(t, admin.QueryRow(ctx, `SELECT reservation_id::text FROM platform.project_preparations`).Scan(&reservation.ReservationID))
	binding.RealmID, binding.ProjectID, binding.ReservationID = "c2000000-0000-4000-8000-000000000001", reservation.ProjectID, reservation.ReservationID
	binding.StorageTarget, binding.SchemaVersion = "primary", 1
	require.NoError(t, physical.QueryRow(ctx, `SELECT oid,datdba,(SELECT oid FROM pg_roles WHERE rolname='authr_a2000000000040008000000000000001')
		FROM pg_database WHERE datname='authp_a2000000000040008000000000000001'`).Scan(&binding.DatabaseOID, &binding.OwnerOID, &binding.RuntimeOID))
	cfg, err := pgxpool.ParseConfig(env("PROVISIONER_CATALOG_URL"))
	require.NoError(t, err)
	cfg.MaxConns, cfg.MinConns = 4, 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	repo, err := preparationpostgres.NewPreparation(pool, binding.RealmID, "primary")
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `ALTER ROLE auth_platform_preparation_test REPLICATION`)
	require.NoError(t, err)
	require.Error(t, repo.CheckRuntime(ctx))
	_, err = admin.Exec(ctx, `ALTER ROLE auth_platform_preparation_test NOREPLICATION`)
	require.NoError(t, err)
	codec, err := credentials.New(root, "root-1")
	require.NoError(t, err)
	missing, err := repo.ReadDatabaseCredential(ctx, reservation, binding, codec)
	require.ErrorIs(t, err, domain.ErrConflict)
	require.Empty(t, missing.Password())
	finished := make(chan error, 4)
	for range 4 {
		go func() { finished <- repo.EnsureSecrets(ctx, reservation, binding, codec) }()
	}
	for range 4 {
		require.NoError(t, <-finished)
	}
	var payload []byte
	var xmin string
	require.NoError(t, admin.QueryRow(ctx, `SELECT ciphertext,xmin::text FROM platform.project_secrets`).Scan(&payload, &xmin))
	require.NoError(t, codec.Verify(binding, credentials.Version, "root-1", payload))
	credentialsReadDrill(t, admin, repo, reservation, binding, codec, payload)
	require.NoError(t, admin.QueryRow(ctx, `SELECT xmin::text FROM platform.project_secrets`).Scan(&xmin))
	assertUnchanged := func(expectedXmin string) {
		t.Helper()
		var actual []byte
		var actualXmin string
		require.NoError(t, admin.QueryRow(ctx, `SELECT ciphertext,xmin::text FROM platform.project_secrets WHERE project_id=$1`, binding.ProjectID).Scan(&actual, &actualXmin))
		require.Equal(t, payload, actual, "ciphertext must remain byte-for-byte identical")
		require.Equal(t, expectedXmin, actualXmin, "replay and wrong roots must not rewrite ciphertext")
	}
	var response bytes.Buffer
	require.NoError(t, preparationcli.Run(ctx, args, protected, &response, io.Discard))
	assertUnchanged(xmin)
	require.Contains(t, response.String(), `"stage":"secrets_stored"`)
	require.NotContains(t, response.String(), root)
	require.NoError(t, physical.QueryRow(ctx, `SELECT rolpassword IS NULL FROM pg_authid WHERE oid=$1`, binding.RuntimeOID).Scan(&clean))
	require.True(t, clean, "-secrets alone must not install a password")
	cancel()
	passwordPreparationDrill(t, physical, protected, args, repo, reservation, binding, codec)
	// Nested drills have their own deadlines; bound this continuation as a separate phase.
	ctx, cancel = context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	// Nested fault drills deliberately tamper/restore secrets; verify bytes before measuring wrong-root calls.
	var restored []byte
	require.NoError(t, admin.QueryRow(ctx, `SELECT ciphertext,xmin::text FROM platform.project_secrets WHERE project_id=$1`, binding.ProjectID).Scan(&restored, &xmin))
	require.Equal(t, payload, restored, "nested drills must restore the exact original ciphertext")

	for _, override := range []map[string]string{
		{"PROVISIONER_MASTER_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32))},
		{"PROVISIONER_MASTER_KEY_ID": "root-2"},
	} {
		wrong := func(key string) string {
			if value, ok := override[key]; ok {
				return value
			}
			return protected(key)
		}
		require.ErrorIs(t, preparationcli.Run(ctx, args, wrong, io.Discard, io.Discard), credentials.ErrUnavailable)
		assertUnchanged(xmin)
	}

	_, err = admin.Exec(ctx, `UPDATE platform.project_secrets SET runtime_oid=(runtime_oid::bigint+1)::oid`)
	require.NoError(t, err)
	require.ErrorIs(t, repo.EnsureSecrets(ctx, reservation, binding, codec), domain.ErrConflict)
	_, err = admin.Exec(ctx, `UPDATE platform.project_secrets SET runtime_oid=$1`, binding.RuntimeOID)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `DELETE FROM platform.project_secrets`)
	require.NoError(t, err)
	missing, err = repo.ReadDatabaseCredential(ctx, reservation, binding, codec)
	require.ErrorIs(t, err, domain.ErrConflict)
	require.Empty(t, missing.Password())
	require.ErrorIs(t, preparationcli.Run(ctx, args, protected, io.Discard, io.Discard), domain.ErrConflict, "lost ciphertext must not regenerate secrets")
	require.NoError(t, admin.QueryRow(ctx, `SELECT secrets_created AND NOT EXISTS(SELECT 1 FROM platform.project_secrets)
		FROM platform.project_preparations`).Scan(&clean))
	require.True(t, clean)
	require.NoError(t, physical.QueryRow(ctx, `SELECT NOT datallowconn AND NOT r.rolcanlogin FROM pg_database db
		JOIN pg_roles r ON r.oid=$1 WHERE db.oid=$2`, binding.RuntimeOID, binding.DatabaseOID).Scan(&clean))
	require.True(t, clean)
	require.NoError(t, physical.QueryRow(ctx, `SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=$1`, binding.RuntimeOID).Scan(&clean))
	require.True(t, clean, "explicit password stage must preserve the installed verifier")
}

func operatorSecretsProfileDrill(t *testing.T, admin *pgx.Conn, env, read func(string) string) {
	t.Helper()
	ctx := t.Context()
	var occupied bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='auth_platform_api_secrets_test')`).Scan(&occupied))
	require.False(t, occupied)
	_, err := admin.Exec(ctx, `CREATE ROLE auth_platform_api_secrets_test LOGIN PASSWORD 'api-fixture-only'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer stop()
		_, err := admin.Exec(cleanup, `DROP OWNED BY auth_platform_api_secrets_test; DROP ROLE auth_platform_api_secrets_test`)
		require.NoError(t, err)
	})
	_, err = admin.Exec(ctx, strings.NewReplacer("auth_platform_runtime", "auth_platform_api_secrets_test", "DATABASE auth_platform ", "DATABASE auth_prepare_catalog_test ").Replace(read("deploy/platform-runtime-grants.sql")))
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(strings.Replace(env("PROVISIONER_CATALOG_URL"), "auth_platform_preparation_test:catalog-fixture-only", "auth_platform_api_secrets_test:api-fixture-only", 1))
	require.NoError(t, err)
	cfg.MaxConns, cfg.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo, err := operatorpostgres.New(pool, operatordomain.RealmID(env("PROVISIONER_REALM_ID")))
	require.NoError(t, err)
	require.NoError(t, repo.CheckRuntime(ctx, false))
	_, err = admin.Exec(ctx, `ALTER ROLE auth_platform_api_secrets_test REPLICATION`)
	require.NoError(t, err)
	require.Error(t, repo.CheckRuntime(ctx, false))
	_, err = admin.Exec(ctx, `ALTER ROLE auth_platform_api_secrets_test NOREPLICATION`)
	require.NoError(t, err)
	for _, grant := range []string{"SELECT(ciphertext) ON platform.project_secrets", "SELECT(key_id) ON platform.project_secrets", "UPDATE(secrets_created) ON platform.project_preparations", "UPDATE(onboarding_admitted) ON platform.project_preparations"} {
		_, err := admin.Exec(ctx, "GRANT "+grant+" TO auth_platform_api_secrets_test")
		require.NoError(t, err)
		require.Error(t, repo.CheckRuntime(ctx, false))
		_, err = admin.Exec(ctx, "REVOKE "+grant+" FROM auth_platform_api_secrets_test")
		require.NoError(t, err)
	}
	require.NoError(t, repo.CheckRuntime(ctx, false))
}
