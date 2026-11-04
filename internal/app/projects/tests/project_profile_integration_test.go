package projects_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	profileapp "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type projectProfileFixture struct {
	admin, db            *pgx.Conn
	rdb                  *redis.Client
	key                  projectruntime.Key
	deps                 projectbinding.ProjectSMTPDependencies
	hash                 *hasher.Bounded
	listener             net.Listener
	sourceUser, password string
}

func (f projectProfileFixture) run(t *testing.T, ctx context.Context) {
	t.Helper()
	_, err := f.db.Exec(ctx, `CREATE TEMP TABLE profile_policy_before AS TABLE auth.auth_settings; CREATE TEMP TABLE profile_providers_before AS TABLE auth.provider_settings;
 UPDATE auth.auth_settings SET version=version+1,password_enabled=false,email_otp_enabled=false,google_enabled=false,telegram_enabled=false,registration_enabled=false,google_registration_enabled=false,telegram_registration_enabled=false,password_email_verification='disabled',token_session_exchange_enabled=false,token_native_enabled=false`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM profile_policy_before;
 DELETE FROM auth.provider_settings; INSERT INTO auth.provider_settings SELECT * FROM profile_providers_before`)
		require.NoError(t, err)
	})
	var origin string
	require.NoError(t, f.admin.QueryRow(ctx, `SELECT origin FROM platform.projects WHERE id=$1`, f.key.Binding.ProjectID).Scan(&origin))
	t.Run("project user directory HTTP", func(t *testing.T) { f.httpUserDirectory(t, ctx, origin) })
	cfg := runtimeprofile.ProjectProfileConfig{Timeout: 10 * time.Second}
	deps := runtimeprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader}}
	t.Run("MFA capability compatibility", func(t *testing.T) { f.mfaCapabilityProfile(t, ctx, origin, deps) })
	closed, err := profileapp.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.True(t, closed.Readiness().Ready)
	require.Empty(t, closed.RoutePlan())
	password := projectPasswordFixtureConfig()
	cfg.BrowserEnabled = true
	cfg.Password = &password
	deps.Redis = f.rdb
	deps.Hash = f.hash
	_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=true,registration_enabled=true`)
	require.NoError(t, err)
	login, err := profileapp.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.True(t, login.Readiness().Ready)
	require.Len(t, login.RoutePlan(), 11)
	_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_email_verification='required'`)
	require.NoError(t, err)
	require.ErrorIs(t, login.CheckCurrent(ctx), settingsdomain.ErrPolicyConflict)
	missingMail, err := profileapp.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.False(t, missingMail.Readiness().Ready)
	require.Len(t, missingMail.RoutePlan(), 7)
	for _, route := range missingMail.RoutePlan() {
		require.Equal(t, "sessions", route.Feature, "mail failure must not hide session management")
	}
	require.Equal(t, "missing_configuration", profileFeature(t, missingMail, "verification").Reason)
	f.providerProfile(t, ctx, origin)
	f.verificationProfile(t, ctx, origin)
	f.tokenProfile(t, ctx, origin)
	t.Run("project HTTP profiles", func(t *testing.T) { f.httpProfile(t, ctx, origin) })
}

func profileFeature(t *testing.T, profile *runtimeprofile.ProjectProfile, feature string) runtimeprofile.ProjectFeatureState {
	t.Helper()
	for _, state := range profile.Readiness().Features {
		if state.Feature == feature {
			return state
		}
	}
	t.Fatalf("missing feature %s", feature)
	return runtimeprofile.ProjectFeatureState{}
}
