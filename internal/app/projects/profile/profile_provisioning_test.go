package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProjectProvisioningPrerequisites(t *testing.T) {
	p := &profileAssembly{origin: "https://project.example.test", states: map[string]runtimeprofile.ProjectFeatureState{}}
	cfg := runtimeprofile.ProjectProfileConfig{EmailManagement: &projectaccount.ProjectEmailConfig{Invitations: accountprovisioning.InvitationConfig{Enabled: true}}}
	p.buildProfileProvisioning(t.Context(), cfg, false)
	require.Empty(t, p.states)
	cfg.BrowserEnabled = true
	p.buildProfileProvisioning(t.Context(), cfg, false)
	require.Equal(t, "origin_mismatch", p.states["provisioning"].Reason)
	require.Equal(t, "origin_mismatch", p.states["invitation_activation"].Reason)
	cfg.EmailManagement.Origin = p.origin
	p.buildProfileProvisioning(t.Context(), cfg, false)
	require.Equal(t, "redis_unavailable", p.states["invitation_activation"].Reason)
	require.Equal(t, "mfa_unavailable", p.states["provisioning"].Reason)
	require.True(t, profileNeedsRedis(cfg, settingsdomain.Policy{}))
	cfg.Password = &projectmethods.ProjectPasswordConfig{}
	cfg.Password.TemporaryPassword.Enabled = true
	p.buildProfileProvisioning(t.Context(), cfg, false)
	require.Equal(t, "password_unavailable", p.states["temporary_password_admin"].Reason)
	p.state("temporary_password", "")
	p.buildProfileProvisioning(t.Context(), cfg, false)
	require.Equal(t, "mfa_unavailable", p.states["temporary_password_admin"].Reason)
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileProvisioning(t.Context(), cfg, false)
	require.True(t, p.featureReady("temporary_password_admin"))
	require.Equal(t, "redis_unavailable", p.states["provisioning"].Reason)
}
