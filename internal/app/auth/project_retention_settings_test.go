package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectRetentionSettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	p.buildProfileRetentionSettings(ProjectProfileConfig{BrowserEnabled: true})
	require.Empty(t, p.RoutePlan())
	cfg := ProjectProfileConfig{RetentionSettingsEnabled: true}
	p.buildProfileRetentionSettings(cfg)
	require.Equal(t, "browser_disabled", p.states["retention_settings_read"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileRetentionSettings(cfg)
	require.True(t, p.featureReady("retention_settings_read"))
	require.Equal(t, "mfa_unavailable", p.states["retention_settings_write"].Reason)
	require.Len(t, p.RoutePlan(), 1)
	p.mfaManagement = &projectMFA{}
	p.buildProfileRetentionSettings(cfg)
	require.True(t, p.featureReady("retention_settings_write"))
	require.Equal(t, []ProjectRoute{
		{Feature: "retention_settings_read", Method: "GET", Path: "/api/v1/admin/auth/settings/retention", Protection: "session_no_refresh"},
		{Feature: "retention_settings_write", Method: "POST", Path: "/api/v1/admin/auth/settings/retention", Protection: "session_no_refresh"},
	}, p.RoutePlan())
}
