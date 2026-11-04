package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProjectUserDirectorySelection(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	p.buildProfileUserDirectory(ProjectProfileConfig{BrowserEnabled: true})
	require.Nil(t, p.userDirectory)
	require.Empty(t, p.RoutePlan())
	p.buildProfileUserDirectory(ProjectProfileConfig{UserDirectoryEnabled: true})
	require.Nil(t, p.userDirectory)
	require.Equal(t, "browser_disabled", p.states["user_directory"].Reason)
	require.Empty(t, p.RoutePlan())
	cfg := ProjectProfileConfig{BrowserEnabled: true, UserDirectoryEnabled: true}
	p.buildProfileUserDirectory(cfg)
	require.NotNil(t, p.userDirectory)
	require.True(t, p.featureReady("user_directory"))
	require.False(t, profileNeedsRedis(cfg, settingsdomain.Policy{}))
	routes := p.RoutePlan()
	require.Equal(t, []ProjectRoute{
		{Feature: "user_directory", Method: "GET", Path: "/api/v1/admin/users", Protection: "session_no_refresh"},
		{Feature: "user_directory", Method: "GET", Path: "/api/v1/admin/users/{id}", Protection: "session_no_refresh"},
	}, routes)
}
