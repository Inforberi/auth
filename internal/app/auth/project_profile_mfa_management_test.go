package auth

import (
	"testing"

	"github.com/stretchr/testify/require"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProjectMFAManagementPrerequisites(t *testing.T) {
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	cfg := ProjectProfileConfig{Password: &ProjectPasswordConfig{}}
	cfg.Password.MFA.Enabled = true
	profile.buildProfileMFAManagement(cfg, "", false)
	require.Empty(t, profile.states, "no browser deployment must not publish management")
	cfg.BrowserEnabled = true
	require.True(t, profileNeedsRedis(cfg, settingsdomain.Policy{}), "management needs Redis even with all primary methods disabled")
	profile.buildProfileMFAManagement(cfg, "", false)
	require.Equal(t, "redis_unavailable", profile.states["mfa_management"].Reason)
	require.Nil(t, profile.mfaManagement)
	cfg.EmailOTP = &ProjectEmailOTPConfig{}
	profile.buildProfileMFAManagement(cfg, "", true)
	require.Equal(t, "inconsistent_browser_policy", profile.states["mfa_management"].Reason)
	require.Nil(t, profile.mfaManagement)
}

func TestProjectMFAManagementRouteProtections(t *testing.T) {
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	profile.state("mfa_management", "redis_unavailable")
	require.Empty(t, profile.RoutePlan())
	profile.state("mfa_management", "")
	routes := profile.RoutePlan()
	require.Len(t, routes, 8)
	methods := map[string]int{}
	for _, route := range routes {
		require.Equal(t, "session_no_refresh", route.Protection)
		methods[route.Method]++
	}
	require.Equal(t, map[string]int{"GET": 1, "POST": 6, "DELETE": 1}, methods)
}
