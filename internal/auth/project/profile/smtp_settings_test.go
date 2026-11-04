package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProjectSMTPSettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	p.buildProfileSMTPSettings(ProjectProfileConfig{BrowserEnabled: true}, "", false)
	require.Empty(t, p.RoutePlan())
	cfg := ProjectProfileConfig{SMTPSettings: &projectsettings.ProjectSMTPSettingsConfig{}}
	p.buildProfileSMTPSettings(cfg, "", false)
	require.Equal(t, "browser_disabled", p.states["smtp_settings_read"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileSMTPSettings(cfg, "", false)
	require.NotNil(t, p.smtpSettings)
	require.True(t, p.featureReady("smtp_settings_read"))
	require.Equal(t, "mfa_unavailable", p.states["smtp_settings_write"].Reason)
	require.Len(t, p.RoutePlan(), 1)
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileSMTPSettings(cfg, "", false)
	require.Equal(t, "redis_unavailable", p.states["smtp_settings_write"].Reason)
	require.True(t, profileNeedsRedis(cfg, settingsdomain.Policy{}))
	p.state("smtp_settings_write", "")
	routes := p.RoutePlan()
	require.Len(t, routes, 3)
	for _, route := range routes {
		require.Equal(t, "session_no_refresh", route.Protection)
	}
}
