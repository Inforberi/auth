package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
)

func TestProjectAuthSettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	p.buildProfileAuthSettings(ProjectProfileConfig{BrowserEnabled: true})
	require.Empty(t, p.RoutePlan())
	cfg := ProjectProfileConfig{AuthSettingsEnabled: true}
	p.buildProfileAuthSettings(cfg)
	require.Equal(t, "browser_disabled", p.states["auth_settings_read"].Reason)
	require.Nil(t, p.authSettings)
	cfg.BrowserEnabled = true
	p.buildProfileAuthSettings(cfg)
	require.NotNil(t, p.authSettings)
	require.True(t, p.featureReady("auth_settings_read"))
	require.Equal(t, "mfa_unavailable", p.states["auth_settings_write"].Reason)
	require.Len(t, p.RoutePlan(), 1)
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileAuthSettings(cfg)
	require.True(t, p.featureReady("auth_settings_write"))
	require.Equal(t, []ProjectRoute{
		{Feature: "auth_settings_read", Method: "GET", Path: "/api/v1/admin/auth/settings", Protection: "session_no_refresh"},
		{Feature: "auth_settings_write", Method: "POST", Path: "/api/v1/admin/auth/settings", Protection: "session_no_refresh"},
	}, p.RoutePlan())
}
