package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProjectUserDirectorySelection(t *testing.T) {
	p := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	p.buildProfileUserDirectory(runtimeprofile.ProjectProfileConfig{BrowserEnabled: true})
	require.Nil(t, p.userDirectory)
	p.buildProfileUserDirectory(runtimeprofile.ProjectProfileConfig{UserDirectoryEnabled: true})
	require.Nil(t, p.userDirectory)
	require.Equal(t, "browser_disabled", p.states["user_directory"].Reason)
	cfg := runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, UserDirectoryEnabled: true}
	p.buildProfileUserDirectory(cfg)
	require.NotNil(t, p.userDirectory)
	require.True(t, p.featureReady("user_directory"))
	require.False(t, profileNeedsRedis(cfg, settingsdomain.Policy{}))
}

func TestProjectUserLifecyclePrerequisites(t *testing.T) {
	p := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	p.buildProfileUserLifecycle(runtimeprofile.ProjectProfileConfig{BrowserEnabled: true})
	require.Empty(t, p.states)
	require.Nil(t, p.userLifecycle)
	cfg := runtimeprofile.ProjectProfileConfig{UserLifecycleEnabled: true}
	p.buildProfileUserLifecycle(cfg)
	require.Equal(t, "browser_disabled", p.states["user_lifecycle"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileUserLifecycle(cfg)
	require.Equal(t, "mfa_unavailable", p.states["user_lifecycle"].Reason)
	require.Nil(t, p.userLifecycle)
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileUserLifecycle(cfg)
	require.NotNil(t, p.userLifecycle)
	require.True(t, p.featureReady("user_lifecycle"))
}
