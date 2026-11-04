package projects_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/database/postgres"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	preparationcli "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/transport/cli"
	preparationapp "github.com/Inforberi/financial-intelligence/internal/app/projects/preparation"
)

func passwordPreparationDrill(t *testing.T, physical *pgx.Conn, env func(string) string, secretsArgs []string, repo *preparationpostgres.PreparationRepository, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) {
	t.Helper()
	ctx := t.Context()
	args := append(append([]string{}, secretsArgs...), "-password")
	_, err := physical.Exec(ctx, `ALTER TABLE provisioning.resources ADD CONSTRAINT fail_password_record CHECK(password_fingerprint IS NULL)`)
	require.NoError(t, err)
	require.Error(t, preparationcli.Run(ctx, args, env, io.Discard, io.Discard))
	var rolledBack bool
	require.NoError(t, physical.QueryRow(ctx, `SELECT r.rolpassword IS NULL AND s.runtime_oid IS NULL AND s.password_fingerprint IS NULL
		FROM provisioning.resources s JOIN pg_authid r ON r.oid=$1`, binding.RuntimeOID).Scan(&rolledBack))
	require.True(t, rolledBack, "journal failure must roll back ALTER ROLE too")
	_, err = physical.Exec(ctx, `ALTER TABLE provisioning.resources DROP CONSTRAINT fail_password_record`)
	require.NoError(t, err)
	value, err := repo.ReadDatabaseCredential(ctx, reservation, binding, codec)
	require.NoError(t, err)
	cfg, err := preparationapp.ConnectionConfig(env("PROVISIONER_STORAGE_URL"))
	require.NoError(t, err)
	trace := &passwordQueryTrace{password: value.Password()}
	cfg.Tracer = trace
	conn, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close(ctx)) }()
	target, err := storage.New(conn, binding.RealmID, binding.StorageTarget)
	require.NoError(t, err)
	_, err = target.Prepare(ctx, reservation)
	require.NoError(t, err)
	authorize := func(check context.Context) error { return repo.CheckCurrent(check, reservation) }
	_, err = target.InstallSchema(ctx, authorize)
	require.NoError(t, err)
	require.ErrorIs(t, target.InstallPassword(ctx, value, nil), domain.ErrConflict)
	require.ErrorIs(t, target.InstallPassword(ctx, credentials.DatabaseCredential{}, authorize), domain.ErrConflict)
	calls := 0
	require.ErrorIs(t, target.InstallPassword(ctx, value, func(context.Context) error {
		calls++
		if calls == 2 {
			return domain.ErrConflict
		}
		return nil
	}), domain.ErrConflict)
	require.NoError(t, physical.QueryRow(ctx, `SELECT rolpassword IS NULL FROM pg_authid WHERE oid=$1`, binding.RuntimeOID).Scan(&rolledBack))
	require.True(t, rolledBack, "authority loss before commit must roll back the password")
	calls = 0
	require.ErrorIs(t, target.InstallPassword(ctx, value, func(context.Context) error {
		calls++
		if calls == 3 {
			return domain.ErrConflict
		}
		return nil
	}), domain.ErrConflict, "late authority loss must not report success")
	require.True(t, trace.sawSCRAM)
	require.False(t, trace.plaintextSeen)
	require.NoError(t, conn.Close(ctx))
	var verifier, xmin string
	require.NoError(t, physical.QueryRow(ctx, `SELECT r.rolpassword,s.xmin::text FROM pg_authid r JOIN provisioning.resources s ON s.runtime_oid=r.oid
		WHERE r.oid=$1`, binding.RuntimeOID).Scan(&verifier, &xmin))
	var response bytes.Buffer
	require.NoError(t, preparationcli.Run(ctx, args, env, &response, io.Discard))
	require.Contains(t, response.String(), `"stage":"password_installed"`)
	require.NotContains(t, response.String(), value.Password())
	require.NotContains(t, response.String(), verifier)
	var same bool
	require.NoError(t, physical.QueryRow(ctx, `SELECT r.rolpassword=$1 AND s.xmin::text=$2 AND NOT r.rolcanlogin AND NOT db.datallowconn
		FROM pg_authid r JOIN provisioning.resources s ON s.runtime_oid=r.oid JOIN pg_database db ON db.oid=s.database_oid`, verifier, xmin).Scan(&same))
	require.True(t, same, "replay must not rotate a password or rewrite its receipt")
	_, err = physical.Exec(ctx, `UPDATE provisioning.resources SET password_fingerprint=decode(repeat('00',32),'hex')`)
	require.NoError(t, err)
	require.ErrorIs(t, preparationcli.Run(ctx, args, env, io.Discard, io.Discard), domain.ErrConflict)
	// Restoring only this synthetic fingerprint does not change the PostgreSQL password.
	fingerprint := sha256.Sum256([]byte(value.Password()))
	_, err = physical.Exec(ctx, `UPDATE provisioning.resources SET password_fingerprint=$1`, fingerprint[:])
	require.NoError(t, err)
	passwordAuthenticationDrill(t, physical, value, binding)
	onboardingPreparationDrill(t, physical, env, args, repo, reservation, binding, codec)
}

type passwordQueryTrace struct {
	password      string
	sawSCRAM      bool
	plaintextSeen bool
}

func (t *passwordQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	t.sawSCRAM = t.sawSCRAM || strings.Contains(data.SQL, "PASSWORD 'SCRAM-SHA-256$")
	t.plaintextSeen = t.plaintextSeen || strings.Contains(data.SQL, t.password) || strings.Contains(fmt.Sprint(data.Args), t.password)
	return ctx
}

func (t *passwordQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func passwordAuthenticationDrill(t *testing.T, physical *pgx.Conn, value credentials.DatabaseCredential, binding credentials.Binding) {
	t.Helper()
	host := os.Getenv("AUTH_STORAGE_TEST_SCRAM_HOST")
	if host == "" {
		t.Log("NOT RUN: TCP SCRAM authentication requires AUTH_STORAGE_TEST_SCRAM_HOST with password-enforcing HBA")
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runtime := "authr_" + strings.ReplaceAll(string(binding.ProjectID), "-", "")
	_, err := physical.Exec(ctx, `ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` LOGIN;
		GRANT CONNECT ON DATABASE auth_storage_test TO `+pgx.Identifier{runtime}.Sanitize())
	require.NoError(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_, err := physical.Exec(cleanup, `ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` NOLOGIN;
			REVOKE CONNECT ON DATABASE auth_storage_test FROM `+pgx.Identifier{runtime}.Sanitize())
		require.NoError(t, err)
	}()
	cfg := physical.Config().Copy()
	cfg.Host, cfg.TLSConfig, cfg.Fallbacks = host, nil, nil
	cfg.User, cfg.Password = runtime, "wrong-fixture-password"
	wrong, err := pgx.ConnectConfig(ctx, cfg)
	if wrong != nil {
		require.NoError(t, wrong.Close(ctx))
	}
	require.Error(t, err, "TCP host auth must not use trust")
	cfg.Password = value.Password()
	correct, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, correct.Close(ctx))
}
