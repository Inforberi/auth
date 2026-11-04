package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

func TestProjectAuthSettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	p.buildProfileAuthSettings(runtimeprofile.ProjectProfileConfig{BrowserEnabled: true})
	cfg := runtimeprofile.ProjectProfileConfig{AuthSettingsEnabled: true}
	p.buildProfileAuthSettings(cfg)
	require.Equal(t, "browser_disabled", p.states["auth_settings_read"].Reason)
	require.Nil(t, p.authSettings)
	cfg.BrowserEnabled = true
	p.buildProfileAuthSettings(cfg)
	require.NotNil(t, p.authSettings)
	require.True(t, p.featureReady("auth_settings_read"))
	require.Equal(t, "mfa_unavailable", p.states["auth_settings_write"].Reason)
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileAuthSettings(cfg)
	require.True(t, p.featureReady("auth_settings_write"))
}

func TestProjectMFASettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	p.buildProfileMFASettings(runtimeprofile.ProjectProfileConfig{BrowserEnabled: true})
	cfg := runtimeprofile.ProjectProfileConfig{MFASettingsEnabled: true}
	p.buildProfileMFASettings(cfg)
	require.Equal(t, "browser_disabled", p.states["mfa_settings"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileMFASettings(cfg)
	require.NotNil(t, p.mfaSettings)
	require.Nil(t, p.mfaManagement, "optional policy read/no-op does not require engine assembly")
}

func TestProjectRetentionSettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	p.buildProfileRetentionSettings(runtimeprofile.ProjectProfileConfig{BrowserEnabled: true})
	cfg := runtimeprofile.ProjectProfileConfig{RetentionSettingsEnabled: true}
	p.buildProfileRetentionSettings(cfg)
	require.Equal(t, "browser_disabled", p.states["retention_settings_read"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileRetentionSettings(cfg)
	require.True(t, p.featureReady("retention_settings_read"))
	require.Equal(t, "mfa_unavailable", p.states["retention_settings_write"].Reason)
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileRetentionSettings(cfg)
	require.True(t, p.featureReady("retention_settings_write"))
}
