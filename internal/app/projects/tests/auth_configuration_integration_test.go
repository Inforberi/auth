package projects_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func authConfigurationDrill(t *testing.T, admin *pgx.Conn, reader *runtimepostgres.RuntimeCredentialReader, key projectruntime.Key, registry *projectruntime.Registry, codec *credentials.Codec) {
	t.Helper()
	ctx := t.Context()
	cfg := admin.Config().Copy()
	var err error
	cfg.Database, _, err = (domain.PreparationReservation{ProjectID: key.Binding.ProjectID, ReservationID: key.Binding.ReservationID}).ResourceNames()
	require.NoError(t, err)
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, db.Close(cleanup))
	})
	var xmin string
	require.NoError(t, db.QueryRow(ctx, `SELECT xmin::text FROM auth.auth_settings`).Scan(&xmin))
	configuration, err := reader.LoadAuthConfiguration(ctx, key, registry)
	require.NoError(t, err)
	require.Equal(t, key, configuration.Key())
	require.EqualValues(t, 1, configuration.Policy().Version)
	require.True(t, configuration.Policy().Policy.Methods.Password)
	var version int
	var keyID string
	var payload []byte
	require.NoError(t, admin.QueryRow(ctx, `SELECT format_version,key_id,ciphertext FROM platform.project_secrets WHERE project_id=$1`, key.Binding.ProjectID).Scan(&version, &keyID, &payload))
	defer clear(payload)
	prepared, err := codec.OpenOnboarding(key.Binding, version, keyID, payload)
	require.NoError(t, err)
	require.True(t, configuration.EncryptionKey() == prepared.EncryptionKey(), "must use the project's sealed data key")
	for _, value := range []any{configuration, &configuration} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			require.Equal(t, "[REDACTED auth configuration]", fmt.Sprintf(format, value))
		}
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `"[REDACTED auth configuration]"`, string(encoded))
	}
	var unchanged bool
	require.NoError(t, db.QueryRow(ctx, `SELECT xmin::text=$1 FROM auth.auth_settings`, xmin).Scan(&unchanged))
	require.True(t, unchanged, "loading must not initialize or rewrite policy")
	for _, change := range []func(*projectruntime.Key){
		func(k *projectruntime.Key) { k.Version++ }, func(k *projectruntime.Key) { k.Generation++ },
		func(k *projectruntime.Key) { k.Binding.RealmID = "a2000000-0000-4000-8000-000000000099" },
		func(k *projectruntime.Key) { k.Binding.ProjectID = "a2000000-0000-4000-8000-000000000099" },
		func(k *projectruntime.Key) { k.Binding.ReservationID = "a2000000-0000-4000-8000-000000000099" },
		func(k *projectruntime.Key) { k.Binding.RuntimeOID++ },
	} {
		stale := key
		change(&stale)
		empty, err := reader.LoadAuthConfiguration(ctx, stale, registry)
		require.ErrorIs(t, err, domain.ErrConflict)
		require.Empty(t, empty.EncryptionKey())
	}
	t.Run("untrusted reader rights", func(t *testing.T) {
		_, err := admin.Exec(ctx, `GRANT UPDATE(name) ON platform.projects TO auth_platform_runtime_reader_test`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := admin.Exec(context.WithoutCancel(ctx), `REVOKE UPDATE(name) ON platform.projects FROM auth_platform_runtime_reader_test`)
			require.NoError(t, err)
		})
		empty, err := reader.LoadAuthConfiguration(ctx, key, registry)
		require.Error(t, err)
		require.Empty(t, empty.EncryptionKey())
	})
	t.Run("corrupt project secrets", func(t *testing.T) {
		corrupted := append([]byte(nil), payload...)
		corrupted[len(corrupted)-1] ^= 1
		_, err := admin.Exec(ctx, `UPDATE platform.project_secrets SET ciphertext=$2 WHERE project_id=$1`, key.Binding.ProjectID, corrupted)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := admin.Exec(context.WithoutCancel(ctx), `UPDATE platform.project_secrets SET ciphertext=$2 WHERE project_id=$1`, key.Binding.ProjectID, payload)
			require.NoError(t, err)
		})
		empty, err := reader.LoadAuthConfiguration(ctx, key, registry)
		require.Error(t, err)
		require.Empty(t, empty.EncryptionKey())
	})
	t.Run("missing policy never initializes", func(t *testing.T) {
		_, err := db.Exec(ctx, `CREATE TEMP TABLE loader_policy_before AS TABLE auth.auth_settings`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(ctx), `INSERT INTO auth.auth_settings SELECT * FROM loader_policy_before`)
			require.NoError(t, err)
		})
		_, err = db.Exec(ctx, `DELETE FROM auth.auth_settings`)
		require.NoError(t, err)
		empty, err := reader.LoadAuthConfiguration(ctx, key, registry)
		require.ErrorIs(t, err, settingsdomain.ErrNotInitialized)
		require.Empty(t, empty.EncryptionKey())
		var count int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.auth_settings`).Scan(&count))
		require.Zero(t, count)
	})
	t.Run("suspend during read discards key and settings", func(t *testing.T) {
		lock, err := db.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = lock.Rollback(context.WithoutCancel(ctx)) }()
		_, err = lock.Exec(ctx, `LOCK TABLE auth.auth_settings IN ACCESS EXCLUSIVE MODE`)
		require.NoError(t, err)
		type outcome struct {
			value runtimepostgres.AuthConfiguration
			err   error
		}
		result := make(chan outcome, 1)
		go func() { value, err := reader.LoadAuthConfiguration(ctx, key, registry); result <- outcome{value, err} }()
		require.Eventually(t, func() bool {
			var waiting bool
			err := lock.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='auth.auth_settings'::regclass AND mode='AccessShareLock' AND NOT granted)`).Scan(&waiting)
			return err == nil && waiting
		}, time.Second, 5*time.Millisecond)
		_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, key.Binding.ProjectID)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := admin.Exec(context.WithoutCancel(ctx), `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, key.Binding.ProjectID, key.Version)
			require.NoError(t, err)
		})
		require.NoError(t, lock.Commit(ctx))
		select {
		case outcome := <-result:
			require.ErrorIs(t, outcome.err, domain.ErrConflict)
			require.Empty(t, outcome.value.EncryptionKey())
		case <-time.After(4 * time.Second):
			t.Fatal("loader failed to finish after releasing policy lock")
		}
	})
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	empty, err := reader.LoadAuthConfiguration(canceled, key, registry)
	require.Error(t, err)
	require.Empty(t, empty.EncryptionKey())
	empty, err = reader.LoadAuthConfiguration(ctx, key, nil)
	require.Error(t, err)
	require.Empty(t, empty.EncryptionKey())
	_, err = reader.LoadAuthConfiguration(ctx, key, registry)
	require.NoError(t, err, "fixture must leave the original runtime usable")
}
