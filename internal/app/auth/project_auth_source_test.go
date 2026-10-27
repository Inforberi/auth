package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func projectDeploymentKey(id projectdomain.ID) projectruntime.Key {
	return projectruntime.Key{Version: 1, Generation: 1, Binding: credentials.Binding{RealmID: "c2000000-0000-4000-8000-000000000001", ProjectID: id, ReservationID: "c2000000-0000-4000-8000-000000000003", StorageTarget: "primary", DatabaseOID: 1, OwnerOID: 2, RuntimeOID: 3, SchemaVersion: 1}}
}

func writeProjectManifest(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "projects.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func deploymentTokenDefaults(cfg *config.Config) {
	cfg.JWT = tokensettings.Config{AccessTTL: 2 * time.Minute, RefreshIdleTTL: time.Hour, RefreshAbsoluteTTL: 2 * time.Hour, ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 3000, IntrospectionConsumerPerMinute: 100, IntrospectionProjectPerMinute: 1000}
	// Public platform flags and key paths never select a project profile.
	cfg.Google.ClientSecret = "synthetic-platform-provider-secret"
	cfg.Google.IPLimit, cfg.Google.GlobalLimit = 30, 1000
	cfg.Telegram.IPLimit, cfg.Telegram.GlobalLimit = 30, 1000
	// All OTP durations/budgets remain operational defaults.
	cfg.EmailOTP.TTL, cfg.EmailOTP.ResendInterval = 5*time.Minute, time.Minute
	cfg.EmailOTP.RequestGlobalLimit, cfg.EmailOTP.ConfirmGlobalLimit = 100, 1000
}

func TestProjectDeploymentWithoutManifestKeepsLimitedProfile(t *testing.T) {
	cfg := operatorConfig("c2000000-0000-4000-8000-000000000001")
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	source, err := LoadProjectAuthDeployment(cfg)
	require.NoError(t, err)
	require.False(t, source.oidc || source.jwt)
	profile, err := source.Profile(t.Context(), projectDeploymentKey("c2000000-0000-4000-8000-000000000002"), "https://alpha.example.test")
	require.NoError(t, err)
	require.True(t, profile.BrowserEnabled)
	require.False(t, profile.UserDirectoryEnabled)
	require.NotNil(t, profile.Password)
	require.Nil(t, profile.Google)
	require.Nil(t, profile.Tokens)
}

func TestProjectDeploymentManifestIsolationAndCopies(t *testing.T) {
	const alpha = "c2000000-0000-4000-8000-000000000002"
	const beta = "c2000000-0000-4000-8000-000000000004"
	cfg := operatorConfig("c2000000-0000-4000-8000-000000000001")
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	cfg.Platform.Delivery.Enabled = true
	deploymentTokenDefaults(cfg)
	manifest := projectAuthManifest{Version: 1, Projects: []projectMethodDeployment{
		{ID: alpha, Browser: true, EmailOTP: true, Reauthentication: true, Google: true, Telegram: true, JWT: &projectJWTDeployment{Native: true, Password: true, Permissions: []accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}}, Resources: []tokenservice.Resource{{Audience: "reports", Permissions: []accessdomain.PermissionKey{"reports.read"}}}, Clients: []tokenservice.IntrospectionClientConfig{{ID: "consumer", SecretHashes: []string{strings.Repeat("a", 64)}, Audiences: []string{"reports"}}}}},
		{ID: beta, Browser: false},
	}}
	manifest.Projects[0].UserDirectory = true
	manifest.Projects[0].EmailBinding, manifest.Projects[0].EmailChange = true, true
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	cfg.Platform.HTTP.ManifestFile = writeProjectManifest(t, data)
	d, err := LoadProjectAuthDeployment(cfg)
	require.NoError(t, err)
	require.True(t, d.oidc && d.jwt)
	ctx := context.Background()
	a, err := d.Profile(ctx, projectDeploymentKey(alpha), "https://alpha.example.test")
	require.NoError(t, err)
	require.True(t, a.EmailOTP.OTP.Enabled && a.EmailOTP.OTP.ReauthenticationEnabled)
	require.Equal(t, "https://alpha.example.test/api/v1/auth/google/callback", a.Google.RedirectURI)
	require.Equal(t, "https://alpha.example.test/api/v1/auth/telegram/callback", a.Telegram.RedirectURI)
	require.Equal(t, "https://alpha.example.test", a.Tokens.Issuer)
	require.Empty(t, a.Verification.EncryptionKey)
	require.True(t, a.UserDirectoryEnabled)
	require.True(t, a.EmailManagement.Binding.Enabled && a.EmailManagement.Change.Enabled)
	require.Equal(t, "https://alpha.example.test/change-email", a.EmailManagement.Change.ConfirmURL)
	require.Equal(t, "https://alpha.example.test/protect-account", a.EmailManagement.Change.ReportURL)
	require.Equal(t, "https://alpha.example.test/recover-account", a.EmailManagement.Change.RecoveryURL)
	require.Empty(t, a.EmailManagement.Verification.EncryptionKey)
	a.EmailManagement.Change.ConfirmURL = "https://foreign.example.test/change-email"
	require.True(t, a.Tokens.Native.PasswordEnabled)
	a.Tokens.Tokens.Resources[0].Permissions[0] = "foreign.read"
	a.Tokens.Introspection.Clients[0].SecretHashes[0] = "invalid"
	a.Google.RedirectURI = "https://foreign.example.test/callback"
	a, err = d.Profile(ctx, projectDeploymentKey(alpha), "https://alpha.example.test")
	require.NoError(t, err)
	require.EqualValues(t, "reports.read", a.Tokens.Tokens.Resources[0].Permissions[0])
	require.Equal(t, strings.Repeat("a", 64), a.Tokens.Introspection.Clients[0].SecretHashes[0])
	require.Equal(t, "https://alpha.example.test/change-email", a.EmailManagement.Change.ConfirmURL)
	for _, id := range []projectdomain.ID{beta, "c2000000-0000-4000-8000-000000000005"} {
		b, err := d.Profile(ctx, projectDeploymentKey(id), "https://other.example.test")
		require.NoError(t, err)
		require.False(t, b.BrowserEnabled)
		require.False(t, b.UserDirectoryEnabled)
		require.Nil(t, b.Google)
		require.Nil(t, b.Tokens)
		require.Nil(t, b.Recovery)
		require.Nil(t, b.EmailManagement)
	}
	foreign := projectDeploymentKey(alpha)
	foreign.Binding.RealmID = "c2000000-0000-4000-8000-000000000006"
	_, err = d.Profile(ctx, foreign, "https://alpha.example.test")
	require.Error(t, err)
}

func TestProjectManifestRejectsAmbiguityAndUnknownSecrets(t *testing.T) {
	_, err := LoadProjectAuthDeployment(nil)
	require.Error(t, err)
	for _, source := range []*ProjectAuthDeployment{nil, {}} {
		_, err := source.Profile(t.Context(), projectruntime.Key{}, "https://alpha.example.test")
		require.Error(t, err)
	}
	for _, input := range []string{
		`{"version":1,"projects":null}`, `{"version":1,"Version":1,"projects":[]}`, `{"version":1,"projects":[]} {}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","google":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","emailChange":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","userDirectory":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","browser":true,"emailBinding":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","issuer":"https://foreign.test"}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","jwt":{"privateKey":"secret"}}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002"},{"id":"c2000000-0000-4000-8000-000000000002"}]}`,
	} {
		_, err := loadProjectAuthManifest(writeProjectManifest(t, []byte(input)))
		require.ErrorIs(t, err, errProjectAuthManifest)
		require.NotContains(t, err.Error(), "secret")
	}
}

func TestProjectManifestValidatesJWTAndRejectsCrossProjectClientSecretReuse(t *testing.T) {
	cfg := operatorConfig("c2000000-0000-4000-8000-000000000001")
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	deploymentTokenDefaults(cfg)
	entry := projectMethodDeployment{ID: "c2000000-0000-4000-8000-000000000002", JWT: &projectJWTDeployment{
		Permissions: []accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}},
		Resources:   []tokenservice.Resource{{Audience: "reports", Permissions: []accessdomain.PermissionKey{"reports.read"}}},
		Clients:     []tokenservice.IntrospectionClientConfig{{ID: "consumer", SecretHashes: []string{strings.Repeat("a", 64)}, Audiences: []string{"reports"}}},
	}}
	for _, test := range []string{"unknown permission", "invalid hash", "shared secret"} {
		t.Run(test, func(t *testing.T) {
			data, err := json.Marshal(projectAuthManifest{Version: 1, Projects: []projectMethodDeployment{entry}})
			require.NoError(t, err)
			var manifest projectAuthManifest
			require.NoError(t, json.Unmarshal(data, &manifest))
			switch test {
			case "unknown permission":
				manifest.Projects[0].JWT.Resources[0].Permissions[0] = "unknown.read"
			case "invalid hash":
				manifest.Projects[0].JWT.Clients[0].SecretHashes[0] = "raw-secret-forbidden"
			case "shared secret":
				other := manifest.Projects[0]
				other.ID = "c2000000-0000-4000-8000-000000000004"
				manifest.Projects = append(manifest.Projects, other)
			}
			data, err = json.Marshal(manifest)
			require.NoError(t, err)
			cfg.Platform.HTTP.ManifestFile = writeProjectManifest(t, data)
			_, err = LoadProjectAuthDeployment(cfg)
			require.ErrorIs(t, err, errProjectAuthManifest)
		})
	}
}
