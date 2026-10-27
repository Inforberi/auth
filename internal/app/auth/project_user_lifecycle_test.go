package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectUserLifecyclePrerequisites(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	p.buildProfileUserLifecycle(ProjectProfileConfig{BrowserEnabled: true})
	require.Empty(t, p.states)
	require.Nil(t, p.userLifecycle)
	cfg := ProjectProfileConfig{UserLifecycleEnabled: true}
	p.buildProfileUserLifecycle(cfg)
	require.Equal(t, "browser_disabled", p.states["user_lifecycle"].Reason)
	cfg.BrowserEnabled = true
	p.buildProfileUserLifecycle(cfg)
	require.Equal(t, "mfa_unavailable", p.states["user_lifecycle"].Reason)
	require.Nil(t, p.userLifecycle)
	require.Empty(t, p.RoutePlan())
	p.mfaManagement = &projectMFA{}
	p.buildProfileUserLifecycle(cfg)
	require.NotNil(t, p.userLifecycle)
	require.True(t, p.featureReady("user_lifecycle"))
	require.Equal(t, []ProjectRoute{
		{Feature: "user_lifecycle", Method: "POST", Path: "/api/v1/admin/users/{id}/status", Protection: "session_no_refresh"},
		{Feature: "user_lifecycle", Method: "DELETE", Path: "/api/v1/admin/users/{id}", Protection: "session_no_refresh"},
	}, p.RoutePlan())
}
