package profile

import (
	"testing"

	"github.com/stretchr/testify/require"

	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProjectProvisioningPrerequisites(t *testing.T) {
	p := &ProjectProfile{origin: "https://project.example.test", states: map[string]ProjectFeatureState{}}
	cfg := ProjectProfileConfig{EmailManagement: &projectaccount.ProjectEmailConfig{Invitations: accountprovisioning.InvitationConfig{Enabled: true}}}
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
	require.Len(t, p.RoutePlan(), 2, "only the two pre-existing temporary user routes are ready")
	p.mfaManagement = &projectmfa.ProjectMFA{}
	p.buildProfileProvisioning(t.Context(), cfg, false)
	require.True(t, p.featureReady("temporary_password_admin"))
	require.Equal(t, "redis_unavailable", p.states["provisioning"].Reason)
}

func TestProjectProvisioningRouteProtection(t *testing.T) {
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	for _, feature := range []string{"provisioning", "invitation_activation", "temporary_password_admin", "user_directory"} {
		p.state(feature, "")
	}
	routes := p.RoutePlan()
	require.Len(t, routes, 7)
	for _, route := range routes {
		if route.Feature == "invitation_activation" {
			require.Equal(t, "browser", route.Protection)
		} else {
			require.Equal(t, "session_no_refresh", route.Protection)
		}
	}
}
