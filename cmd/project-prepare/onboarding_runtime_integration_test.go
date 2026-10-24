package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func onboardingRuntimeDrill(t *testing.T, physical *pgx.Conn, env func(string) string, repo *catalog.PreparationRepository, r domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) {
	t.Helper()
	ctx := t.Context()
	keys, err := repo.ReadOnboardingKeys(ctx, r, binding, codec)
	require.NoError(t, err)
	stale := r
	stale.Generation++
	empty, err := repo.ReadOnboardingKeys(ctx, stale, binding, codec)
	require.ErrorIs(t, err, domain.ErrConflict)
	require.Empty(t, empty.SetupSecret())
	database, _, err := r.ResourceNames()
	require.NoError(t, err)
	runtime := "authr_a2000000000040008000000000000001"
	_, err = physical.Exec(ctx, `ALTER DATABASE `+pgx.Identifier{database}.Sanitize()+` ALLOW_CONNECTIONS true;
		ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` LOGIN;
		GRANT CONNECT ON DATABASE `+pgx.Identifier{database}.Sanitize()+` TO `+pgx.Identifier{runtime}.Sanitize())
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := physical.Exec(cleanup, `REVOKE CONNECT ON DATABASE `+pgx.Identifier{database}.Sanitize()+` FROM `+pgx.Identifier{runtime}.Sanitize()+`;
			ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` NOLOGIN;
			ALTER DATABASE `+pgx.Identifier{database}.Sanitize()+` ALLOW_CONNECTIONS false`)
		require.NoError(t, err)
	}()
	poolFor := func(user string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(physical.Config().ConnString())
		require.NoError(t, err)
		cfg.ConnConfig.Database, cfg.ConnConfig.User = database, user
		cfg.MaxConns, cfg.MinConns = 1, 0
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, err)
		return pool
	}
	privileged := poolFor(physical.Config().User)
	defer privileged.Close()
	require.Error(t, catalog.CheckOnboardingRuntime(ctx, privileged, keys.Proof()), "reject executor/superuser as runtime")
	pool := poolFor(runtime)
	defer pool.Close()
	require.NoError(t, catalog.CheckOnboardingRuntime(ctx, pool, keys.Proof()))
	require.ErrorIs(t, catalog.CheckManagedRuntime(ctx, pool, keys.Proof()), domain.ErrConflict)
	wrong := binding
	wrong.RuntimeOID++
	wrongPayload, err := codec.Generate(wrong)
	require.NoError(t, err)
	wrongKeys, err := codec.OpenOnboarding(wrong, credentials.Version, codec.KeyID(), wrongPayload)
	require.NoError(t, err)
	require.ErrorIs(t, catalog.CheckOnboardingRuntime(ctx, pool, wrongKeys.Proof()), domain.ErrConflict)
	_, err = physical.Exec(ctx, `ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` BYPASSRLS`)
	require.NoError(t, err)
	require.ErrorIs(t, catalog.CheckOnboardingRuntime(ctx, pool, keys.Proof()), domain.ErrConflict)
	_, err = physical.Exec(ctx, `ALTER ROLE `+pgx.Identifier{runtime}.Sanitize()+` NOBYPASSRLS`)
	require.NoError(t, err)
	_, err = privileged.Exec(ctx, `GRANT USAGE ON SCHEMA project_meta TO `+pgx.Identifier{runtime}.Sanitize())
	require.NoError(t, err)
	require.ErrorIs(t, catalog.CheckOnboardingRuntime(ctx, pool, keys.Proof()), domain.ErrConflict)
	_, err = privileged.Exec(ctx, `REVOKE USAGE ON SCHEMA project_meta FROM `+pgx.Identifier{runtime}.Sanitize())
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { require.NoError(t, rdb.Close()) }()
	apiConfig, err := pgxpool.ParseConfig(strings.Replace(env("PROVISIONER_CATALOG_URL"), "auth_platform_preparation_test:catalog-fixture-only@", "auth_platform_api_secrets_test:api-fixture-only@", 1))
	require.NoError(t, err)
	apiConfig.MaxConns, apiConfig.MinConns = 1, 0
	api, err := pgxpool.NewWithConfig(ctx, apiConfig)
	require.NoError(t, err)
	defer api.Close()
	adminConfig := apiConfig.Copy()
	adminConfig.ConnConfig.User, adminConfig.ConnConfig.Password = "auth", ""
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	require.NoError(t, err)
	defer admin.Close()
	deps := appauth.ProjectOnboardingDependencies{
		Pool: pool, Redis: rdb, Logger: zap.NewNop(),
		Hash:    hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1),
		Catalog: api,
	}
	cfg := appauth.ProjectOnboardingConfig{
		Project: domain.Project{
			ID: r.ProjectID, Slug: "test-project", Origin: "https://test.example.test",
			DesiredState: domain.Enabled, Phase: domain.Provisioning, Version: r.Version, Generation: r.Generation,
		},
		Keys: keys, SMTPAllowedTargets: []string{"smtp.example.test:587"},
		Reservation: r,
		HTTP:        requestmiddleware.CapacityConfig{MaxInFlight: 2, RequestTimeout: time.Second},
	}
	onboardingAdmissionDrill(t, admin, api, pool, repo, cfg.Project, r, binding, codec)
	handler, err := appauth.NewProjectOnboarding(ctx, cfg, deps)
	require.ErrorIs(t, err, settingsdomain.ErrNotInitialized)
	require.Nil(t, handler, "must not fall back to platform/environment SMTP")
	scope, err := realmscope.New("project", string(r.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("smtp-settings:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(keys.EncryptionKey(), purpose)
	require.NoError(t, err)
	password, err := cipher.Seal([]byte("smtp-fixture-password"))
	require.NoError(t, err)
	stored, err := settingspostgres.New(pool).InitializeSMTP(ctx, settingsservice.SMTPStored{
		SMTPSnapshot: settingsdomain.SMTPSnapshot{Version: 1, PasswordSet: true, Config: settingsdomain.SMTPConfig{
			Host: "smtp.example.test", Port: 587, Username: "fixture", From: "auth@example.test", Domain: "test.example.test", RequireTLS: true,
		}}, Password: password,
	})
	require.NoError(t, err)
	handler, err = appauth.NewProjectOnboarding(ctx, cfg, deps)
	require.NoError(t, err)
	require.NotNil(t, handler)
	_, err = admin.Exec(ctx, `UPDATE platform.project_preparations SET onboarding_admitted=false WHERE project_id=$1`, r.ProjectID)
	require.NoError(t, err)
	request := httptest.NewRequest("POST", cfg.Project.Origin+"/api/v1/setup/start", nil)
	request.Header.Set("Origin", cfg.Project.Origin)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, 404, response.Code, "admission must be checked again after construction")
	require.NoError(t, pool.Ping(ctx), "runtime must not close borrowed pool")
	after, err := settingspostgres.New(pool).LoadSMTP(ctx)
	require.NoError(t, err)
	require.Equal(t, stored, after, "construction must not rewrite SMTP settings")
	require.NoError(t, repo.PermitOnboarding(ctx, r, binding, codec, pool))
	denied := cfg
	denied.SMTPAllowedTargets = []string{"other.example.test:587"}
	handler, err = appauth.NewProjectOnboarding(ctx, denied, deps)
	require.ErrorIs(t, err, settingsdomain.ErrInvalidSMTP)
	require.Nil(t, handler)
	tampered := append([]byte{}, stored.Password...)
	tampered[len(tampered)-1] ^= 1
	_, err = privileged.Exec(ctx, `UPDATE auth.smtp_settings SET password=$1`, tampered)
	require.NoError(t, err)
	handler, err = appauth.NewProjectOnboarding(ctx, cfg, deps)
	require.Error(t, err)
	require.Nil(t, handler)
	_, err = privileged.Exec(ctx, `UPDATE auth.smtp_settings SET password=$1`, stored.Password)
	require.NoError(t, err)
	onboardingAssemblySuspendDrill(t, admin, privileged, physical, cfg, deps)
	_, err = privileged.Exec(ctx, `DELETE FROM auth.smtp_settings`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE platform.project_preparations SET onboarding_admitted=false WHERE project_id=$1`, r.ProjectID)
	require.NoError(t, err)
}
