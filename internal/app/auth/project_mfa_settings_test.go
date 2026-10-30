package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectMFASettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	p.buildProfileMFASettings(ProjectProfileConfig{BrowserEnabled: true})
	require.Empty(t, p.RoutePlan())
	cfg := ProjectProfileConfig{MFASettingsEnabled: true}
	p.buildProfileMFASettings(cfg)
	require.Equal(t, "browser_disabled", p.states["mfa_settings"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileMFASettings(cfg)
	require.NotNil(t, p.mfaSettings)
	require.Nil(t, p.mfaManagement, "optional policy read/no-op does not require engine assembly")
	require.Equal(t, []ProjectRoute{
		{Feature: "mfa_settings", Method: "GET", Path: "/api/v1/admin/auth/settings/mfa", Protection: "session_no_refresh"},
		{Feature: "mfa_settings", Method: "POST", Path: "/api/v1/admin/auth/settings/mfa", Protection: "session_no_refresh"},
	}, p.RoutePlan())
}

func TestProjectMFASettingsManifest(t *testing.T) {
	require.False(t, validProjectMethodDeployment(projectMethodDeployment{MFASettings: true}))
	require.True(t, validProjectMethodDeployment(projectMethodDeployment{Browser: true, MFASettings: true}))
	d := &ProjectAuthDeployment{}
	profile := d.browserProfile(ProjectProfileConfig{Password: &ProjectPasswordConfig{}}, projectMethodDeployment{Browser: true, MFASettings: true})
	require.True(t, profile.MFASettingsEnabled)
	require.False(t, (&ProjectAuthDeployment{}).browserProfile(ProjectProfileConfig{}, projectMethodDeployment{}).MFASettingsEnabled)
}
