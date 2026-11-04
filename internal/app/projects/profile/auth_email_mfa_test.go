package profile

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	appfixtures "github.com/Inforberi/financial-intelligence/internal/app/tests/fixtures"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func emailMFADeploymentConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := appfixtures.OperatorConfig("c2000000-0000-4000-8000-000000000001")
	appfixtures.DeploymentTokenDefaults(cfg)
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	cfg.Platform.Delivery.Enabled = true
	cfg.Platform.Delivery.SMTPAllowedTargets = "smtp.example.test:587"
	cfg.Platform.HTTP.EmailMFA = config.ProjectEmailMFAConfig{PreparationTTL: 3 * time.Minute, PreparationResendInterval: time.Minute, PreparationRequestsPerProjectMinute: 100, PreparationConfirmsPerProjectMinute: 1000, UserChangesPerMinute: 5, ProjectChangesPerMinute: 500}
	return cfg
}

func TestEmailMFADeploymentIsScopedAndPreservesOperatorConfig(t *testing.T) {
	const alpha projectdomain.ID = "c2000000-0000-4000-8000-000000000002"
	const beta projectdomain.ID = "c2000000-0000-4000-8000-000000000004"
	cfg := emailMFADeploymentConfig(t)
	data, err := json.Marshal(projectAuthManifest{Version: 1, Projects: []projectMethodDeployment{
		{ID: alpha, Browser: true, EmailMFA: true, EmailOTP: true, Google: true, Telegram: true, MFASettings: true, JWT: &projectJWTDeployment{
			Native: true, Password: true,
			Permissions: []accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}}, Resources: []tokenservice.Resource{{Audience: "reports", Permissions: []accessdomain.PermissionKey{"reports.read"}}},
		}},
		{ID: beta, Browser: true},
	}})
	require.NoError(t, err)
	cfg.Platform.HTTP.ManifestFile = appfixtures.WriteProjectManifest(t, data)
	before := *cfg
	d, err := LoadProjectAuthDeployment(cfg)
	require.NoError(t, err)
	a, err := d.Profile(t.Context(), projectDeploymentKey(alpha), "https://alpha.example.test")
	require.NoError(t, err)
	require.NotNil(t, a.EmailMFA)
	require.True(t, a.Password.MFA.RecoveryEnabled)
	require.True(t, a.EmailOTP.MFA.RecoveryEnabled && a.Google.MFA.RecoveryEnabled && a.Telegram.MFA.RecoveryEnabled)
	require.True(t, a.Tokens.Native.MFA.RecoveryEnabled)
	require.False(t, cfg.MFA.RecoveryEnabled, "project recovery is independent of operator recovery")
	require.Equal(t, before, *cfg)
	a.EmailMFA.Factors.UserMutationsPerMinute = 999
	a.Password.MFA.RecoveryEnabled = false
	alphaAgain, err := d.Profile(t.Context(), projectDeploymentKey(alpha), "https://alpha.example.test")
	require.NoError(t, err)
	require.Equal(t, 5, alphaAgain.EmailMFA.Factors.UserMutationsPerMinute)
	require.True(t, alphaAgain.Password.MFA.RecoveryEnabled)
	b, err := d.Profile(t.Context(), projectDeploymentKey(beta), "https://beta.example.test")
	require.NoError(t, err)
	require.Nil(t, b.EmailMFA)
	require.False(t, b.Password.MFA.RecoveryEnabled)
	foreign := projectDeploymentKey(alpha)
	foreign.Binding.RealmID = beta
	_, err = d.Profile(t.Context(), foreign, "https://alpha.example.test")
	require.ErrorIs(t, err, projectdomain.ErrConflict)
	require.Equal(t, before, *cfg)
}

func TestEmailMFADeploymentRejectsMissingDependencies(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*config.Config)
	}{
		{"MFA disabled", func(c *config.Config) { c.MFA.Enabled = false }},
		{"MFA invalid", func(c *config.Config) { c.MFA.Issuer = "" }},
		{"delivery disabled", func(c *config.Config) { c.Platform.Delivery.Enabled = false }},
		{"SMTP empty", func(c *config.Config) { c.Platform.Delivery.SMTPAllowedTargets = "" }},
		{"SMTP whitespace", func(c *config.Config) { c.Platform.Delivery.SMTPAllowedTargets = "  " }},
		{"SMTP invalid port", func(c *config.Config) { c.Platform.Delivery.SMTPAllowedTargets = "smtp.example.test:invalid" }},
		{"SMTP empty member", func(c *config.Config) { c.Platform.Delivery.SMTPAllowedTargets = "smtp.example.test:587," }},
		{"preparation TTL", func(c *config.Config) { c.Platform.HTTP.EmailMFA.PreparationTTL = 6 * time.Minute }},
		{"resend interval", func(c *config.Config) { c.Platform.HTTP.EmailMFA.PreparationResendInterval = 3 * time.Minute }},
		{"request budget", func(c *config.Config) { c.Platform.HTTP.EmailMFA.PreparationRequestsPerProjectMinute = 0 }},
		{"confirm budget", func(c *config.Config) { c.Platform.HTTP.EmailMFA.PreparationConfirmsPerProjectMinute = 0 }},
		{"user changes", func(c *config.Config) { c.Platform.HTTP.EmailMFA.UserChangesPerMinute = 0 }},
		{"project changes", func(c *config.Config) { c.Platform.HTTP.EmailMFA.ProjectChangesPerMinute = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := emailMFADeploymentConfig(t)
			test.change(cfg)
			_, err := compileProjectEmailMFA(cfg)
			require.ErrorIs(t, err, errProjectAuthManifest)
		})
	}
	require.False(t, validProjectMethodDeployment(projectMethodDeployment{EmailMFA: true}))
	require.True(t, validProjectMethodDeployment(projectMethodDeployment{Browser: true, EmailMFA: true}))
	cfg := emailMFADeploymentConfig(t)
	cfg.Platform.HTTP.EmailMFA.UserChangesPerMinute = 0
	cfg.Platform.HTTP.ManifestFile = appfixtures.WriteProjectManifest(t, []byte(`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","browser":true}]}`))
	d, err := LoadProjectAuthDeployment(cfg)
	require.NoError(t, err, "unused capability does not impose email-specific dependencies")
	profile, err := d.Profile(t.Context(), projectDeploymentKey("c2000000-0000-4000-8000-000000000002"), "https://alpha.example.test")
	require.NoError(t, err)
	require.Nil(t, profile.EmailMFA)
}

func TestEmailMFAWithoutManifestStaysDisabled(t *testing.T) {
	cfg := emailMFADeploymentConfig(t)
	cfg.MFA.RecoveryEnabled = true
	d, err := LoadProjectAuthDeployment(cfg)
	require.NoError(t, err)
	profile, err := d.Profile(t.Context(), projectDeploymentKey("c2000000-0000-4000-8000-000000000002"), "https://alpha.example.test")
	require.NoError(t, err)
	require.Nil(t, profile.EmailMFA)
	require.False(t, profile.Password.MFA.RecoveryEnabled)
	require.True(t, cfg.MFA.RecoveryEnabled)
	for _, raw := range []string{
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","emailMFA":true}]}`,
		`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","browser":true,"emailMFA":"true"}]}`,
	} {
		_, err := loadProjectAuthManifest(appfixtures.WriteProjectManifest(t, []byte(raw)))
		require.ErrorIs(t, err, errProjectAuthManifest)
	}
}
