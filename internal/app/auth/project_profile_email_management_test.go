package auth

import (
	"testing"

	"github.com/stretchr/testify/require"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
)

func TestProjectEmailManagementPrerequisitesAreIndependent(t *testing.T) {
	profile := &ProjectProfile{origin: "https://alpha.example.test", states: map[string]ProjectFeatureState{}}
	email := &ProjectEmailConfig{Origin: profile.origin, Binding: accountemail.EmailBindingConfig{Enabled: true}, Change: accountemail.EmailChangeConfig{Enabled: true}}
	cfg := ProjectProfileConfig{EmailManagement: email}
	profile.buildProfileEmailManagement(t.Context(), cfg, false)
	require.Empty(t, profile.states, "browser disabled does not publish management")
	cfg.BrowserEnabled = true
	profile.buildProfileEmailManagement(t.Context(), cfg, false)
	require.Equal(t, "mfa_unavailable", profile.states["email_binding"].Reason)
	require.Equal(t, "redis_unavailable", profile.states["email_change"].Reason)
	cfg.EmailOTP = &ProjectEmailOTPConfig{}
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

func TestProjectEmailManagementRouteProtections(t *testing.T) {
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	profile.state("email_binding", "")
	profile.state("email_binding_confirmation", "")
	profile.state("email_change", "")
	profile.state("email_change_protection", "")
	want := map[string]string{
		"/api/v1/admin/users/{id}/email-binding": "session_no_refresh",
		"/api/v1/auth/email/binding/confirm":     "session_no_refresh",
		"/api/v1/auth/email/change":              "session_no_refresh",
		"/api/v1/auth/email/change/confirm":      "browser",
		"/api/v1/auth/email/change/report":       "browser",
		"/api/v1/auth/email/change/recover":      "browser",
	}
	require.Len(t, profile.RoutePlan(), len(want))
	for _, route := range profile.RoutePlan() {
		require.Equal(t, "POST", route.Method)
		require.Equal(t, want[route.Path], route.Protection)
	}
}
