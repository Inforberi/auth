package main

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	storage "github.com/Inforberi/financial-intelligence/internal/platform/project/storage/postgres"
)

func onboardingPreparationDrill(t *testing.T, physical *pgx.Conn, env func(string) string, passwordArgs []string, repo *catalog.PreparationRepository, r domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) {
	t.Helper()
	ctx := t.Context()
	args := append(append([]string{}, passwordArgs...), "-onboarding")
	proof, err := repo.ReadSetupProof(ctx, r, binding, codec)
	require.NoError(t, err)
	require.NotEmpty(t, proof.Digest())
	stale := r
	stale.Generation++
	empty, err := repo.ReadSetupProof(ctx, stale, binding, codec)
	require.ErrorIs(t, err, domain.ErrConflict)
	require.Empty(t, empty.Digest())
	database, _, err := r.ResourceNames()
	require.NoError(t, err)
	inspect := func(check func(*pgx.Conn)) {
		_, err := physical.Exec(ctx, `ALTER DATABASE `+pgx.Identifier{database}.Sanitize()+` ALLOW_CONNECTIONS true`)
		require.NoError(t, err)
		cfg := physical.Config().Copy()
		cfg.Database = database
		conn, err := pgx.ConnectConfig(ctx, cfg)
		require.NoError(t, err)
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			require.NoError(t, conn.Close(cleanup))
			_, err := physical.Exec(cleanup, `ALTER DATABASE `+pgx.Identifier{database}.Sanitize()+` ALLOW_CONNECTIONS false`)
			require.NoError(t, err)
		}()
		check(conn)
	}
	t.Run("managed configuration", func(t *testing.T) {
		managedPreparationDrill(t, physical, env, passwordArgs, repo, r, binding, codec, inspect)
	})
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `ALTER TABLE project_meta.identity ADD CONSTRAINT fail_onboarding CHECK(NOT configuration_prepared)`)
		require.NoError(t, err)
	})
	require.Error(t, run(ctx, args, env, io.Discard, io.Discard))
	inspect(func(conn *pgx.Conn) {
		var clean bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT NOT configuration_prepared AND NOT EXISTS(SELECT 1 FROM auth.auth_settings)
			AND NOT EXISTS(SELECT 1 FROM auth.initial_setup) FROM project_meta.identity`).Scan(&clean))
		require.True(t, clean, "marker failure must roll back both settings and setup pin")
		_, err := conn.Exec(ctx, `ALTER TABLE project_meta.identity DROP CONSTRAINT fail_onboarding;
			INSERT INTO auth.initial_setup(singleton) VALUES(true)`)
		require.NoError(t, err)
	})
	require.ErrorIs(t, run(ctx, args, env, io.Discard, io.Discard), domain.ErrConflict, "must not adopt unmarked setup state")
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `DELETE FROM auth.initial_setup`)
		require.NoError(t, err)
	})
	cfg, err := connectionConfig(env("PROVISIONER_STORAGE_URL"))
	require.NoError(t, err)
	conn, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close(ctx)) }()
	target, err := storage.New(conn, binding.RealmID, binding.StorageTarget)
	require.NoError(t, err)
	_, err = target.Prepare(ctx, r)
	require.NoError(t, err)
	authorize := func(check context.Context) error { return repo.CheckCurrent(check, r) }
	_, err = target.InstallSchema(ctx, authorize)
	require.NoError(t, err)
	require.ErrorIs(t, target.PrepareOnboarding(ctx, credentials.SetupProof{}, authorize), domain.ErrConflict)
	runtime := "authr_a2000000000040008000000000000001"
	_, err = physical.Exec(ctx, `ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` LOGIN`)
	require.NoError(t, err)
	require.ErrorIs(t, target.PrepareOnboarding(ctx, proof, authorize), domain.ErrConflict)
	var sealed bool
	require.NoError(t, physical.QueryRow(ctx, `SELECT NOT datallowconn FROM pg_database WHERE oid=$1`, binding.DatabaseOID).Scan(&sealed))
	require.True(t, sealed, "unsafe runtime must be rejected before opening the project database")
	_, err = physical.Exec(ctx, `ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` NOLOGIN`)
	require.NoError(t, err)
	calls := 0
	require.ErrorIs(t, target.PrepareOnboarding(ctx, proof, func(context.Context) error {
		calls++
		if calls == 2 {
			return domain.ErrConflict
		}
		return nil
	}), domain.ErrConflict)
	require.NoError(t, conn.Close(ctx))
	inspect(func(conn *pgx.Conn) {
		var clean bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT NOT configuration_prepared AND NOT EXISTS(SELECT 1 FROM auth.auth_settings)
			AND NOT EXISTS(SELECT 1 FROM auth.initial_setup) FROM project_meta.identity`).Scan(&clean))
		require.True(t, clean, "authority loss before commit must roll back initialization")
	})
	var response bytes.Buffer
	require.NoError(t, run(ctx, args, env, &response, io.Discard))
	require.Contains(t, response.String(), `"stage":"onboarding_prepared"`)
	require.NotContains(t, response.String(), proof.Digest())
	managedArgs := append(append([]string{}, passwordArgs...), "-managed")
	require.ErrorIs(t, run(ctx, managedArgs, env, io.Discard, io.Discard), domain.ErrConflict)
	var markerXmin, policyXmin, setupXmin string
	var policyBefore []byte
	inspect(func(conn *pgx.Conn) {
		var safe bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT m.configuration_prepared AND m.setup_operator_hash=$1 AND p.version=1 AND p.password_enabled
			AND NOT(p.email_otp_enabled OR p.google_enabled OR p.telegram_enabled OR p.registration_enabled OR p.google_registration_enabled
			OR p.telegram_registration_enabled OR p.token_session_exchange_enabled OR p.token_native_enabled)
			AND p.password_email_verification='disabled' AND s.operator_hash=$1 AND s.initialized_at IS NULL AND s.administrator_id IS NULL
			AND s.payload IS NULL AND NOT EXISTS(SELECT 1 FROM auth.users) AND NOT EXISTS(SELECT 1 FROM auth.roles),
			m.xmin::text,p.xmin::text,s.xmin::text,to_jsonb(p) FROM project_meta.identity m CROSS JOIN auth.auth_settings p CROSS JOIN auth.initial_setup s`,
			proof.Digest()).Scan(&safe, &markerXmin, &policyXmin, &setupXmin, &policyBefore))
		require.True(t, safe)
	})
	onboardingRuntimeDrill(t, physical, env, repo, r, binding, codec)
	onboardingSMTPDrill(t, physical, env, repo, r, binding, codec)
	inspect(func(conn *pgx.Conn) {
		// SMTP adds only its own retained receipt, not a policy/setup rewrite.
		var unchanged bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT m.xmin::text,m.smtp_prepared AND p.xmin::text=$1 AND s.xmin::text=$2
			FROM project_meta.identity m CROSS JOIN auth.auth_settings p CROSS JOIN auth.initial_setup s`, policyXmin, setupXmin).Scan(&markerXmin, &unchanged))
		require.True(t, unchanged)
	})
	markerXmin = onboardingActivationDrill(t, physical, env, repo, r, binding, codec, markerXmin)
	inspect(func(conn *pgx.Conn) {
		// The policy drill writes and restores settings; measure replay from that restored row.
		var restored bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT xmin::text,to_jsonb(p)=$1::jsonb FROM auth.auth_settings p`, policyBefore).Scan(&policyXmin, &restored))
		require.True(t, restored, "administrative drills must restore the exact prepared policy")
	})
	require.NoError(t, run(ctx, args, env, io.Discard, io.Discard))
	inspect(func(conn *pgx.Conn) {
		var same bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT m.xmin::text=$1 AND p.xmin::text=$2 AND s.xmin::text=$3
			FROM project_meta.identity m CROSS JOIN auth.auth_settings p CROSS JOIN auth.initial_setup s`, markerXmin, policyXmin, setupXmin).Scan(&same))
		require.True(t, same, "replay must not overwrite settings, marker or setup proof")
		_, err := conn.Exec(ctx, `UPDATE auth.initial_setup SET operator_hash=repeat('0',64)`)
		require.NoError(t, err)
	})
	require.ErrorIs(t, run(ctx, args, env, io.Discard, io.Discard), domain.ErrConflict)
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `UPDATE auth.initial_setup SET operator_hash=$1`, proof.Digest())
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `UPDATE auth.auth_settings SET google_enabled=true`)
		require.NoError(t, err)
	})
	require.ErrorIs(t, run(ctx, args, env, io.Discard, io.Discard), domain.ErrConflict)
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `UPDATE auth.auth_settings SET google_enabled=false; DELETE FROM auth.initial_setup`)
		require.NoError(t, err)
	})
	require.ErrorIs(t, run(ctx, args, env, io.Discard, io.Discard), domain.ErrConflict, "lost setup must not be recreated")
	inspect(func(conn *pgx.Conn) {
		var missing bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT configuration_prepared AND NOT EXISTS(SELECT 1 FROM auth.initial_setup)
			FROM project_meta.identity`).Scan(&missing))
		require.True(t, missing)
	})
}
