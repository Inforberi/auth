package profile

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
)

func projectEmailMFAFixtureConfig() projectmfa.ProjectEmailMFAConfig {
	return projectmfa.ProjectEmailMFAConfig{Preparation: otpservice.EmailPreparationConfig{TTL: 3 * time.Minute, ResendInterval: time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 100}, Factors: mfamanagement.EmailFactorConfig{UserMutationsPerMinute: 5, ProjectMutationsPerMinute: 500}}
}

func TestProjectEmailMFAReadiness(t *testing.T) {
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	profile.buildProfileEmailMFA(ProjectProfileConfig{})
	require.Empty(t, profile.states)
	invalid := projectmfa.ProjectEmailMFAConfig{}
	profile.buildProfileEmailMFA(ProjectProfileConfig{EmailMFA: &invalid})
	require.False(t, profile.featureReady("email_mfa"))
	valid := projectEmailMFAFixtureConfig()
	cfg := ProjectProfileConfig{BrowserEnabled: true, EmailMFA: &valid, Password: &projectmethods.ProjectPasswordConfig{}}
	profile.buildProfileEmailMFA(cfg)
	require.Equal(t, "password_mfa_recovery_required", profile.states["email_mfa"].Reason)
	cfg.Password.MFA.Enabled, cfg.Password.MFA.RecoveryEnabled = true, true
	profile.buildProfileEmailMFA(cfg)
	require.Equal(t, "mfa_recovery_unavailable", profile.states["email_mfa"].Reason)
	profile.mfaManagement = &projectmfa.ProjectMFA{}
	profile.mfaRecovery = projectmfa.NewProjectMFARecovery(profile.mfaManagement, &projectaccount.ProjectEmailRuntime{})
	profile.buildProfileEmailMFA(cfg)
	require.True(t, profile.featureReady("email_mfa"))
	require.False(t, profile.featureReady("email_mfa_login"), "owner management must not enable a disabled primary")
	profile.state("password", "")
	profile.buildProfileEmailMFA(cfg)
	require.True(t, profile.featureReady("email_mfa_login"))
	for _, route := range profile.RoutePlan() {
		if route.Feature == "email_mfa" {
			require.Equal(t, "session_no_refresh", route.Protection)
		}
		if route.Feature == "email_mfa_login" {
			require.Equal(t, "browser", route.Protection)
		}
	}
}
