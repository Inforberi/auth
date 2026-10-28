package auth

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectProviderSettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	p.buildProfileProviderSettings(ProjectProfileConfig{BrowserEnabled: true}, "")
	require.Empty(t, p.RoutePlan())
	cfg := ProjectProfileConfig{ProviderSettingsEnabled: true}
	p.buildProfileProviderSettings(cfg, "")
	require.Equal(t, "browser_disabled", p.states["provider_settings_read"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileProviderSettings(cfg, "")
	require.True(t, p.featureReady("provider_settings_read"))
	require.Equal(t, "mfa_unavailable", p.states["provider_settings_write"].Reason)
	require.Len(t, p.RoutePlan(), 1)
	p.key = projectDeploymentKey("c2000000-0000-4000-8000-000000000002")
	p.mfaManagement = &projectMFA{}
	p.buildProfileProviderSettings(cfg, "invalid-root")
	require.Equal(t, "component_unavailable", p.states["provider_settings_write"].Reason)
	p.buildProfileProviderSettings(cfg, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	require.True(t, p.featureReady("provider_settings_write"))
	require.Len(t, p.RoutePlan(), 2)
	for _, route := range p.RoutePlan() {
		require.Equal(t, "session_no_refresh", route.Protection)
	}
}
