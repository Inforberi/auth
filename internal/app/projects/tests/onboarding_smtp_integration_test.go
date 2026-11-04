package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/storage/postgres"
	preparationapp "github.com/Inforberi/financial-intelligence/internal/app/projects/preparation"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func onboardingSMTPDrill(t *testing.T, physical *pgx.Conn, env func(string) string, repo *preparationpostgres.PreparationRepository, r domain.PreparationReservation, b credentials.Binding, codec *credentials.Codec) {
	t.Helper()
	ctx := t.Context()
	keys, err := repo.ReadOnboardingKeys(ctx, r, b, codec)
	require.NoError(t, err)
	authorize := func(check context.Context) error { return repo.CheckCurrent(check, r) }
	input := storage.OnboardingSMTP{Config: settingsdomain.SMTPConfig{
		Host: "smtp.example.test", Port: 587, Username: "fixture", From: "auth@example.test", Domain: "example.test", RequireTLS: true,
	}, Password: "project-smtp-fixture-only", AllowedTargets: []string{"smtp.example.test:587"}}
	prepare := func(value storage.OnboardingSMTP, material credentials.OnboardingKeys, check func(context.Context) error) (settingsdomain.SMTPSnapshot, error) {
		cfg, err := preparationapp.ConnectionConfig(env("PROVISIONER_STORAGE_URL"))
		require.NoError(t, err)
		conn, err := pgx.ConnectConfig(ctx, cfg)
		require.NoError(t, err)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			require.NoError(t, conn.Close(cleanup))
		}()
		target, err := storage.New(conn, b.RealmID, b.StorageTarget)
		require.NoError(t, err)
		_, err = target.Prepare(ctx, r)
		require.NoError(t, err)
		_, err = target.InstallSchema(ctx, authorize)
		require.NoError(t, err)
		return target.PrepareSMTP(ctx, material, value, check)
	}
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
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			require.NoError(t, conn.Close(cleanup))
			_, err := physical.Exec(cleanup, `ALTER DATABASE `+pgx.Identifier{database}.Sanitize()+` ALLOW_CONNECTIONS false`)
			require.NoError(t, err)
		}()
		check(conn)
	}
	checkSealed := func() {
		var sealed bool
		require.NoError(t, physical.QueryRow(ctx, `SELECT NOT d.datallowconn AND NOT role.rolcanlogin
			AND NOT has_database_privilege(role.oid,d.oid,'CONNECT') FROM pg_database d JOIN pg_roles role ON role.oid=$2
			WHERE d.oid=$1`, b.DatabaseOID, b.RuntimeOID).Scan(&sealed))
		require.True(t, sealed)
	}
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `ALTER TABLE project_meta.identity ADD CONSTRAINT fail_smtp_receipt CHECK(NOT smtp_prepared)`)
		require.NoError(t, err)
	})
	result, err := prepare(input, keys, authorize)
	require.Error(t, err)
	require.Zero(t, result)
	checkSealed()
	inspect(func(conn *pgx.Conn) {
		var rolledBack bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT NOT smtp_prepared AND NOT EXISTS(SELECT 1 FROM auth.smtp_settings) FROM project_meta.identity`).Scan(&rolledBack))
		require.True(t, rolledBack)
		_, err := conn.Exec(ctx, `ALTER TABLE project_meta.identity DROP CONSTRAINT fail_smtp_receipt`)
		require.NoError(t, err)
	})
	for _, failAt := range []int{2, 3} {
		calls := 0
		result, err := prepare(input, keys, func(check context.Context) error {
			calls++
			if calls == failAt {
				return domain.ErrConflict
			}
			return repo.CheckCurrent(check, r)
		})
		require.ErrorIs(t, err, domain.ErrConflict)
		require.Zero(t, result)
		checkSealed()
		inspect(func(conn *pgx.Conn) {
			var persisted bool
			require.NoError(t, conn.QueryRow(ctx, `SELECT smtp_prepared AND EXISTS(SELECT 1 FROM auth.smtp_settings) FROM project_meta.identity`).Scan(&persisted))
			require.Equal(t, failAt == 3, persisted, "late authority loss may leave committed settings, never public access")
		})
	}
	var markerXmin, smtpXmin string
	var stored settingssmtp.SMTPStored
	inspect(func(conn *pgx.Conn) {
		require.NoError(t, conn.QueryRow(ctx, `SELECT version,configuration,password_set,password FROM auth.smtp_settings WHERE singleton`).Scan(
			&stored.Version, &stored.Config, &stored.PasswordSet, &stored.Password,
		))
		require.Equal(t, input.Config, stored.Config)
		require.EqualValues(t, 1, stored.Version)
		require.True(t, stored.PasswordSet)
		require.NotContains(t, string(stored.Password), input.Password)
		require.NoError(t, conn.QueryRow(ctx, `SELECT m.xmin::text,s.xmin::text FROM project_meta.identity m CROSS JOIN auth.smtp_settings s`).Scan(&markerXmin, &smtpXmin))
	})
	scope, err := realmscope.New("project", string(b.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("smtp-settings:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(keys.EncryptionKey(), purpose)
	require.NoError(t, err)
	plain, err := cipher.Open(stored.Password)
	require.NoError(t, err)
	require.Equal(t, input.Password, string(plain))
	clear(plain)
	foreign, err := secretbox.NewScoped(keys.EncryptionKey(), "smtp-settings:v1")
	require.NoError(t, err)
	_, err = foreign.Open(stored.Password)
	require.Error(t, err, "platform/unscoped cipher must not decrypt project SMTP")
	result, err = prepare(input, keys, authorize)
	require.NoError(t, err)
	require.Equal(t, stored.SMTPSnapshot, result)
	inspect(func(conn *pgx.Conn) {
		var immutable bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT m.xmin::text=$1 AND s.xmin::text=$2
			AND NOT EXISTS(SELECT 1 FROM auth.users) AND NOT EXISTS(SELECT 1 FROM auth.roles)
			FROM project_meta.identity m CROSS JOIN auth.smtp_settings s`, markerXmin, smtpXmin).Scan(&immutable))
		require.True(t, immutable, "no replay write or copied platform owner")
	})
	for _, mutate := range []func(*storage.OnboardingSMTP){
		func(s *storage.OnboardingSMTP) { s.Password = "different-fixture-password" },
		func(s *storage.OnboardingSMTP) { s.Config.Username = "different-user" },
	} {
		wrong := input
		mutate(&wrong)
		result, err := prepare(wrong, keys, authorize)
		require.ErrorIs(t, err, domain.ErrConflict)
		require.Zero(t, result)
	}
	invalid := input
	invalid.Config.RequireTLS = false
	result, err = prepare(invalid, keys, authorize)
	require.ErrorIs(t, err, settingsdomain.ErrInvalidSMTP)
	require.Zero(t, result)
	checkSealed()
	inspect(func(conn *pgx.Conn) {
		tampered := append([]byte{}, stored.Password...)
		tampered[len(tampered)-1] ^= 1
		_, err := conn.Exec(ctx, `UPDATE auth.smtp_settings SET password=$1`, tampered)
		require.NoError(t, err)
	})
	result, err = prepare(input, keys, authorize)
	require.ErrorIs(t, err, domain.ErrConflict)
	require.Zero(t, result)
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `UPDATE auth.smtp_settings SET password=$1;`, stored.Password)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `UPDATE project_meta.identity SET smtp_prepared=false`)
		require.NoError(t, err)
	})
	result, err = prepare(input, keys, authorize)
	require.ErrorIs(t, err, domain.ErrConflict, "must not adopt an unmarked row")
	require.Zero(t, result)
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `UPDATE project_meta.identity SET smtp_prepared=true; DELETE FROM auth.smtp_settings`)
		require.NoError(t, err)
	})
	result, err = prepare(input, keys, authorize)
	require.ErrorIs(t, err, domain.ErrConflict, "retained receipt forbids reseeding a missing row")
	require.Zero(t, result)
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `INSERT INTO auth.smtp_settings(singleton,configuration,password,password_set)
			VALUES(true,$1,$2,$3)`, stored.Config, stored.Password, stored.PasswordSet)
		require.NoError(t, err)
	})
	checkSealed()
}
