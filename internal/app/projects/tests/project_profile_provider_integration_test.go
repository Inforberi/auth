package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	profileapp "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func (f projectProfileFixture) providerProfile(t *testing.T, ctx context.Context, origin string) {
	t.Helper()
	_, err := f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=false,registration_enabled=false,google_enabled=true,password_email_verification='optional'`)
	require.NoError(t, err)
	owners := projectmethods.NewProjectOIDCClients(ctx)
	t.Cleanup(owners.Close)
	google := projectmethods.ProjectOIDCConfig{Provider: "google", Enabled: true, RedirectURI: origin + "/api/v1/auth/google/callback", IPLimit: 30, GlobalLimit: 1000, Session: projectPasswordFixtureConfig().Session, Timeout: 5 * time.Second}
	cfg := runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Google: &google, Timeout: 10 * time.Second}
	deps := runtimeprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb}, OIDCClients: owners}
	missing, err := profileapp.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.False(t, missing.Readiness().Ready)
	require.Len(t, missing.RoutePlan(), 7)
	for _, route := range missing.RoutePlan() {
		require.Equal(t, "sessions", route.Feature)
	}
	require.Equal(t, "provider_credentials_unavailable", profileFeature(t, missing, "google").Reason)
	configuration, err := f.deps.Reader.LoadAuthConfiguration(ctx, f.key, f.deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(f.key.Binding.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("provider-google:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	secret, err := cipher.Seal([]byte("synthetic-profile-provider-secret"))
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `INSERT INTO auth.provider_settings(provider,version,client_id,secret,secret_set) VALUES('google',1,'profile.apps.googleusercontent.com',$1,true)
 ON CONFLICT(provider) DO UPDATE SET version=auth.provider_settings.version+1,client_id=EXCLUDED.client_id,secret=EXCLUDED.secret,secret_set=true`, secret)
	require.NoError(t, err)
	ready, err := profileapp.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.True(t, ready.Readiness().Ready)
	require.Len(t, ready.RoutePlan(), 11)
	// A missing password config must not remove an independently assembled Google flow.
	_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=true,password_email_verification='disabled'`)
	require.NoError(t, err)
	partial, err := profileapp.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.False(t, partial.Readiness().Ready)
	require.Len(t, partial.RoutePlan(), 11)
	require.True(t, profileFeature(t, partial, "google").Ready)
	require.Equal(t, "missing_configuration", profileFeature(t, partial, "password").Reason)
	foreign := google
	foreign.RedirectURI = "https://foreign.example.test/api/v1/auth/google/callback"
	cfg.Google = &foreign
	blocked, err := profileapp.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.Len(t, blocked.RoutePlan(), 7)
	for _, route := range blocked.RoutePlan() {
		require.Equal(t, "sessions", route.Feature)
	}
	require.Equal(t, "origin_or_provider_mismatch", profileFeature(t, blocked, "google").Reason)
}
