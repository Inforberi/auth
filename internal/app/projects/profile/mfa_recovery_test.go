package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfarecovery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/service"
)

func TestProjectMFARecoveryPrerequisites(t *testing.T) {
	cfg := ProjectProfileConfig{Password: &projectmethods.ProjectPasswordConfig{}}
	cfg.Password.MFA.RecoveryEnabled = true
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	profile.buildProfileMFARecovery(t.Context(), cfg, "", false)
	require.Equal(t, "browser_disabled", profile.states["mfa_recovery"].Reason)
	cfg.BrowserEnabled = true
	profile.buildProfileMFARecovery(t.Context(), cfg, "", false)
	require.Equal(t, "mfa_unavailable", profile.states["mfa_recovery"].Reason)
	profile.mfa = &projectmfa.ProjectMFA{}
	profile.state("mfa", "")
	profile.buildProfileMFARecovery(t.Context(), cfg, "", false)
	require.Equal(t, "redis_unavailable", profile.states["mfa_recovery"].Reason)
	profile.buildProfileMFARecovery(t.Context(), cfg, "", true)
	require.Equal(t, "delivery_not_running", profile.states["mfa_recovery"].Reason)
	require.Nil(t, profile.mfaRecovery)
	for _, route := range profile.RoutePlan() {
		require.NotEqual(t, "mfa_recovery", route.Feature)
	}
	profile.state("mfa", "disabled")
	cfg.Password.MFA.RecoveryEnabled = false
	profile = &ProjectProfile{states: map[string]ProjectFeatureState{}}
	profile.buildProfileMFARecovery(t.Context(), cfg, "", true)
	require.Empty(t, profile.states, "disabled recovery does not require dependencies")
}

func TestProjectMFARecoveryUnavailable(t *testing.T) {
	for _, service := range []*projectmfa.ProjectMFARecovery{nil, {}} {
		candidate, err := service.Start(t.Context(), mfarecovery.StartRecoveryInput{})
		require.ErrorIs(t, err, domain.ErrUnavailable)
		require.Nil(t, candidate)
		codes, err := service.Complete(t.Context(), mfarecovery.CompleteRecoveryInput{})
		require.ErrorIs(t, err, domain.ErrUnavailable)
		require.Nil(t, codes)
	}
}

func TestProjectMFARecoveryRouteProtections(t *testing.T) {
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	profile.state("mfa_recovery", "")
	routes := profile.RoutePlan()
	require.Len(t, routes, 2)
	for _, route := range routes {
		require.Equal(t, "POST", route.Method)
		require.Equal(t, "browser", route.Protection, "recovery uses challenge binding and Origin, not an authenticated session")
	}
}
