package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfarecovery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/service"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

func TestProjectMFARecoveryPrerequisites(t *testing.T) {
	cfg := runtimeprofile.ProjectProfileConfig{Password: &projectmethods.ProjectPasswordConfig{}}
	cfg.Password.MFA.RecoveryEnabled = true
	profile := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
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
	profile.state("mfa", "disabled")
	cfg.Password.MFA.RecoveryEnabled = false
	profile = &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
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
