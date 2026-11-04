package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProjectMFAManagementPrerequisites(t *testing.T) {
	profile := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	cfg := runtimeprofile.ProjectProfileConfig{Password: &projectmethods.ProjectPasswordConfig{}}
	cfg.Password.MFA.Enabled = true
	profile.buildProfileMFAManagement(cfg, "", false)
	require.Empty(t, profile.states, "no browser deployment must not publish management")
	cfg.BrowserEnabled = true
	require.True(t, profileNeedsRedis(cfg, settingsdomain.Policy{}), "management needs Redis even with all primary methods disabled")
	profile.buildProfileMFAManagement(cfg, "", false)
	require.Equal(t, "redis_unavailable", profile.states["mfa_management"].Reason)
	require.Nil(t, profile.mfaManagement)
	cfg.EmailOTP = &projectmethods.ProjectEmailOTPConfig{}
	profile.buildProfileMFAManagement(cfg, "", true)
	require.Equal(t, "inconsistent_browser_policy", profile.states["mfa_management"].Reason)
	require.Nil(t, profile.mfaManagement)
}
