package profile

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	appfixtures "github.com/Inforberi/financial-intelligence/internal/app/tests/fixtures"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func projectDeploymentKey(id projectdomain.ID) projectruntime.Key {
	return projectruntime.Key{Version: 1, Generation: 1, Binding: credentials.Binding{RealmID: "c2000000-0000-4000-8000-000000000001", ProjectID: id, ReservationID: "c2000000-0000-4000-8000-000000000003", StorageTarget: "primary", DatabaseOID: 1, OwnerOID: 2, RuntimeOID: 3, SchemaVersion: 1}}
}

func TestProjectDeploymentWithoutManifestKeepsLimitedProfile(t *testing.T) {
	cfg := appfixtures.OperatorConfig("c2000000-0000-4000-8000-000000000001")
	cfg.Invitation.Enabled, cfg.TemporaryPassword.Enabled = true, true
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	source, err := LoadProjectAuthDeployment(cfg)
	require.NoError(t, err)
	require.False(t, source.oidc || source.jwt)
	profile, err := source.Profile(t.Context(), projectDeploymentKey("c2000000-0000-4000-8000-000000000002"), "https://alpha.example.test")
	require.NoError(t, err)
	require.True(t, profile.BrowserEnabled)
	require.False(t, profile.UserDirectoryEnabled)
	require.False(t, profile.UserLifecycleEnabled)
	require.False(t, profile.AuthSettingsEnabled)
	require.False(t, profile.ProviderSettingsEnabled)
	require.False(t, profile.RetentionSettingsEnabled)
	require.Nil(t, profile.SMTPSettings)
	require.Nil(t, profile.Access)
	require.False(t, profile.Password.TemporaryPassword.Enabled)
	require.NotNil(t, profile.Password)
	require.Nil(t, profile.Google)
	require.Nil(t, profile.Tokens)
}

func TestProjectDeploymentManifestIsolationAndCopies(t *testing.T) {
	const alpha = "c2000000-0000-4000-8000-000000000002"
	const beta = "c2000000-0000-4000-8000-000000000004"
	cfg := appfixtures.OperatorConfig("c2000000-0000-4000-8000-000000000001")
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	cfg.Platform.Delivery.Enabled = true
	appfixtures.DeploymentTokenDefaults(cfg)
	manifest := projectAuthManifest{Version: 1, Projects: []projectMethodDeployment{
		{ID: alpha, Browser: true, EmailOTP: true, Reauthentication: true, Google: true, Telegram: true, JWT: &projectJWTDeployment{Native: true, Password: true, Permissions: []accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}}, Resources: []tokenservice.Resource{{Audience: "reports", Permissions: []accessdomain.PermissionKey{"reports.read"}}}, Clients: []tokenservice.IntrospectionClientConfig{{ID: "consumer", SecretHashes: []string{strings.Repeat("a", 64)}, Audiences: []string{"reports"}}}}},
		{ID: beta, Browser: false},
	}}
	manifest.Projects[0].Access = &projectAccessDeployment{Permissions: []accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}}}
	manifest.Projects[0].Invitations, manifest.Projects[0].TemporaryPassword = true, true
	cfg.Invitation = accountprovisioning.InvitationConfig{TTL: time.Hour, ActivationGlobalLimit: 100, ReissueCooldown: time.Minute, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100}
	cfg.TemporaryPassword = passwordprovisioning.TemporaryPasswordConfig{TTL: time.Hour, SetupTTL: time.Minute, ReissueCooldown: time.Minute, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100, SetupProjectAttemptsPerMinute: 100}
	manifest.Projects[0].ProviderSettings = true
	manifest.Projects[0].RetentionSettings = true
	manifest.Projects[0].SMTPSettings = true
	cfg.Platform.Delivery.SMTPAllowedTargets = "smtp.example.test:587"
	manifest.Projects[0].AuthSettings = true
	manifest.Projects[0].UserDirectory, manifest.Projects[0].UserLifecycle = true, true
	manifest.Projects[0].EmailBinding, manifest.Projects[0].EmailChange = true, true
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	cfg.Platform.HTTP.ManifestFile = appfixtures.WriteProjectManifest(t, data)
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
	require.True(t, a.UserLifecycleEnabled)
	require.True(t, a.AuthSettingsEnabled)
	require.True(t, a.ProviderSettingsEnabled)
	require.True(t, a.RetentionSettingsEnabled)
	require.Equal(t, []string{"smtp.example.test:587"}, a.SMTPSettings.AllowedTargets)
	require.NotNil(t, a.Access)
	require.True(t, a.Access.Contains("reports.read"))
	require.True(t, a.Access.Contains(accesssettings.RolesManage))
	require.True(t, a.EmailManagement.Invitations.Enabled)
	require.Equal(t, "https://alpha.example.test/activate", a.EmailManagement.Invitations.URL)
	require.True(t, a.Password.TemporaryPassword.Enabled)
	require.True(t, a.EmailManagement.Binding.Enabled && a.EmailManagement.Change.Enabled)
	require.Equal(t, "https://alpha.example.test/change-email", a.EmailManagement.Change.ConfirmURL)
	require.Equal(t, "https://alpha.example.test/protect-account", a.EmailManagement.Change.ReportURL)
	require.Equal(t, "https://alpha.example.test/recover-account", a.EmailManagement.Change.RecoveryURL)
	require.Empty(t, a.EmailManagement.Verification.EncryptionKey)
	a.SMTPSettings.AllowedTargets[0] = "forbidden.example.test:587"
	a.Password.TemporaryPassword.Enabled = false
	a.EmailManagement.Invitations.URL = "https://foreign.example.test/activate"
	a.EmailManagement.Change.ConfirmURL = "https://foreign.example.test/change-email"
	require.True(t, a.Tokens.Native.PasswordEnabled)
	a.Tokens.Tokens.Resources[0].Permissions[0] = "foreign.read"
	a.Tokens.Introspection.Clients[0].SecretHashes[0] = "invalid"
	a.Google.RedirectURI = "https://foreign.example.test/callback"
	a, err = d.Profile(ctx, projectDeploymentKey(alpha), "https://alpha.example.test")
	require.NoError(t, err)
	require.True(t, a.Password.TemporaryPassword.Enabled)
	require.Equal(t, []string{"smtp.example.test:587"}, a.SMTPSettings.AllowedTargets)
	require.Equal(t, "https://alpha.example.test/activate", a.EmailManagement.Invitations.URL)
	require.EqualValues(t, "reports.read", a.Tokens.Tokens.Resources[0].Permissions[0])
	require.Equal(t, strings.Repeat("a", 64), a.Tokens.Introspection.Clients[0].SecretHashes[0])
	require.Equal(t, "https://alpha.example.test/change-email", a.EmailManagement.Change.ConfirmURL)
	for _, id := range []projectdomain.ID{beta, "c2000000-0000-4000-8000-000000000005"} {
		b, err := d.Profile(ctx, projectDeploymentKey(id), "https://other.example.test")
		require.NoError(t, err)
		require.False(t, b.BrowserEnabled)
		require.False(t, b.UserDirectoryEnabled)
		require.False(t, b.UserLifecycleEnabled)
		require.False(t, b.AuthSettingsEnabled)
		require.False(t, b.ProviderSettingsEnabled)
		require.False(t, b.RetentionSettingsEnabled)
		require.Nil(t, b.SMTPSettings)
		require.Nil(t, b.Access)
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
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","userLifecycle":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","authSettings":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","smtpSettings":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","providerSettings":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","retentionSettings":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","access":{}}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","invitations":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","temporaryPassword":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","browser":true,"emailBinding":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","issuer":"https://foreign.test"}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","jwt":{"privateKey":"secret"}}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002"},{"id":"c2000000-0000-4000-8000-000000000002"}]}`,
	} {
		_, err := loadProjectAuthManifest(appfixtures.WriteProjectManifest(t, []byte(input)))
		require.ErrorIs(t, err, errProjectAuthManifest)
		require.NotContains(t, err.Error(), "secret")
	}
}

func TestProjectManifestValidatesJWTAndRejectsCrossProjectClientSecretReuse(t *testing.T) {
	cfg := appfixtures.OperatorConfig("c2000000-0000-4000-8000-000000000001")
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	appfixtures.DeploymentTokenDefaults(cfg)
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
			cfg.Platform.HTTP.ManifestFile = appfixtures.WriteProjectManifest(t, data)
			_, err = LoadProjectAuthDeployment(cfg)
			require.ErrorIs(t, err, errProjectAuthManifest)
		})
	}
}
