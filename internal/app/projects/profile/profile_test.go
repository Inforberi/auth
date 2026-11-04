package profile

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestClosedProfileAndRedisSelection(t *testing.T) {
	policy := settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Telegram: true}, PasswordEmailVerification: settingsdomain.VerificationOptional}
	require.False(t, profileNeedsRedis(runtimeprofile.ProjectProfileConfig{}, policy))
	require.False(t, profileNeedsRedis(runtimeprofile.ProjectProfileConfig{Tokens: &projectnative.ProjectTokenConfig{Enabled: true}}, policy))
	require.True(t, profileNeedsRedis(runtimeprofile.ProjectProfileConfig{BrowserEnabled: true}, policy))
}

func TestBrowserSessionManagementDoesNotDependOnLoginMethods(t *testing.T) {
	profile := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}}
	profile.buildProfileMethods(t.Context(), runtimeprofile.ProjectProfileConfig{BrowserEnabled: false}, false)
	require.Empty(t, profile.states)
	profile.buildProfileMethods(t.Context(), runtimeprofile.ProjectProfileConfig{BrowserEnabled: true}, false)
	require.True(t, profile.featureReady("sessions"))
}

func TestProfileRejectsInconsistentBrowserSessionPolicies(t *testing.T) {
	profile := &profileAssembly{states: map[string]runtimeprofile.ProjectFeatureState{}, password: &projectmethods.ProjectPassword{}, google: &projectmethods.ProjectOIDC{}}
	profile.state("password", "")
	profile.state("google", "")
	profile.bindBrowserMFA("", []projectmethods.BrowserPolicy{
		{Feature: "password", Session: sessionservice.Config{SessionTTL: time.Hour}},
		{Feature: "google", Session: sessionservice.Config{SessionTTL: 2 * time.Hour}},
	})
	require.Nil(t, profile.password)
	require.Nil(t, profile.google)
	require.False(t, profile.featureReady("password"))
	require.False(t, profile.featureReady("google"))
}
