package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/app/projects/native"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (f projectProfileFixture) tokenProfile(t *testing.T, ctx context.Context, origin string) {
	t.Helper()
	_, err := f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_email_verification='disabled',token_session_exchange_enabled=true`)
	require.NoError(t, err)
	client, err := projectnative.NewProjectTokenRedis(f.rdb)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	catalog, err := accesssettings.NewCatalog([]accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}})
	require.NoError(t, err)
	tokens := projectnative.ProjectTokenConfig{Enabled: true, Issuer: origin, Catalog: catalog, Limits: tokenredis.DefaultLimits(), Timeout: 5 * time.Second, Tokens: tokenservice.Config{AccessTTL: time.Minute, Resources: []tokenservice.Resource{{Audience: "reports", Permissions: []accessdomain.PermissionKey{"reports.read"}}}}}
	cfg := projectprofile.ProjectProfileConfig{Tokens: &tokens, Timeout: 10 * time.Second}
	// Exchange-only needs the issuance Redis owner, not the ordinary password/MFA client.
	deps := projectprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, IssuanceRedis: client}}
	profile, err := projectprofile.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.True(t, profile.Readiness().Ready)
	require.True(t, profileFeature(t, profile, "exchange").Ready)
	require.Len(t, profile.RoutePlan(), 3)
	bad := tokens
	bad.Issuer = "https://foreign-issuer.example.test"
	cfg.Tokens = &bad
	rejected, err := projectprofile.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.Empty(t, rejected.RoutePlan())
	require.Equal(t, "origin_mismatch", profileFeature(t, rejected, "tokens").Reason)
	_, err = projectprofile.BuildProjectProfile(ctx, f.key, "https://foreign-origin.example.test", cfg, deps)
	require.Error(t, err)
}
