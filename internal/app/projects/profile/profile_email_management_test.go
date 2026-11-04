package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

func TestProjectEmailManagementPrerequisitesAreIndependent(t *testing.T) {
	profile := &profileAssembly{origin: "https://alpha.example.test", states: map[string]runtimeprofile.ProjectFeatureState{}}
	email := &projectaccount.ProjectEmailConfig{Origin: profile.origin, Binding: accountemail.EmailBindingConfig{Enabled: true}, Change: accountemail.EmailChangeConfig{Enabled: true}}
	cfg := runtimeprofile.ProjectProfileConfig{EmailManagement: email}
	profile.buildProfileEmailManagement(t.Context(), cfg, false)
	require.Empty(t, profile.states, "browser disabled does not publish management")
	cfg.BrowserEnabled = true
	profile.buildProfileEmailManagement(t.Context(), cfg, false)
	require.Equal(t, "mfa_unavailable", profile.states["email_binding"].Reason)
	require.Equal(t, "redis_unavailable", profile.states["email_change"].Reason)
	cfg.EmailOTP = &projectmethods.ProjectEmailOTPConfig{}
	cfg.EmailOTP.MFA.Enabled = true
	profile.buildProfileEmailManagement(t.Context(), cfg, false)
	require.Equal(t, "reauthentication_unavailable", profile.states["email_binding"].Reason)
	profile.state("reauthentication", "")
	profile.buildProfileEmailManagement(t.Context(), cfg, false)
	require.Equal(t, "redis_unavailable", profile.states["email_binding"].Reason)
	email.Origin = "https://foreign.example.test"
	profile.buildProfileEmailManagement(t.Context(), cfg, true)
	require.Equal(t, "origin_mismatch", profile.states["email_binding"].Reason)
	require.Equal(t, "origin_mismatch", profile.states["email_change"].Reason)
	require.Nil(t, profile.binding)
	require.Nil(t, profile.change)
}
