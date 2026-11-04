package profile

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProjectProviderSettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	p.buildProfileProviderSettings(runtimeprofile.ProjectProfileConfig{BrowserEnabled: true}, "")
	cfg := runtimeprofile.ProjectProfileConfig{ProviderSettingsEnabled: true}
	p.buildProfileProviderSettings(cfg, "")
	require.Equal(t, "browser_disabled", p.states["provider_settings_read"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileProviderSettings(cfg, "")
	require.True(t, p.featureReady("provider_settings_read"))
	require.Equal(t, "mfa_unavailable", p.states["provider_settings_write"].Reason)
	p.key = providerSettingsKey("c2000000-0000-4000-8000-000000000002")
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileProviderSettings(cfg, "invalid-root")
	require.Equal(t, "component_unavailable", p.states["provider_settings_write"].Reason)
	p.buildProfileProviderSettings(cfg, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	require.True(t, p.featureReady("provider_settings_write"))
}

func providerSettingsKey(id projectdomain.ID) projectruntime.Key {
	return projectruntime.Key{Version: 1, Generation: 1, Binding: credentials.Binding{RealmID: "c2000000-0000-4000-8000-000000000001", ProjectID: id, ReservationID: "c2000000-0000-4000-8000-000000000003", StorageTarget: "primary", DatabaseOID: 1, OwnerOID: 2, RuntimeOID: 3, SchemaVersion: 1}}
}

func TestProjectSMTPSettingsPrerequisitesAndRoutes(t *testing.T) {
	p := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	p.buildProfileSMTPSettings(runtimeprofile.ProjectProfileConfig{BrowserEnabled: true}, "", false)
	cfg := runtimeprofile.ProjectProfileConfig{SMTPSettings: &projectsettings.ProjectSMTPSettingsConfig{}}
	p.buildProfileSMTPSettings(cfg, "", false)
	require.Equal(t, "browser_disabled", p.states["smtp_settings_read"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileSMTPSettings(cfg, "", false)
	require.NotNil(t, p.smtpSettings)
	require.True(t, p.featureReady("smtp_settings_read"))
	require.Equal(t, "mfa_unavailable", p.states["smtp_settings_write"].Reason)
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileSMTPSettings(cfg, "", false)
	require.Equal(t, "redis_unavailable", p.states["smtp_settings_write"].Reason)
	require.True(t, profileNeedsRedis(cfg, settingsdomain.Policy{}))
}
