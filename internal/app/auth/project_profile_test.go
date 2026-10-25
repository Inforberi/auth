package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProfileRoutesExcludeUnavailableAndDefendReturnedSnapshots(t *testing.T) {
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	profile.state("password", "missing_configuration")
	profile.state("google", "")
	profile.state("native_email", "delivery_not_running")
	report := profile.Readiness()
	require.False(t, report.Ready)
	routes := profile.RoutePlan()
	require.Len(t, routes, 2)
	require.Equal(t, ProjectRoute{Feature: "google", Method: "POST", Path: "/api/v1/auth/google/start", Protection: "browser"}, routes[0])
	require.Equal(t, "callback", routes[1].Protection)
	routes[0].Path = "/untrusted"
	report.Features[0].Ready = true
	require.NotEqual(t, "/untrusted", profile.RoutePlan()[0].Path)
	require.False(t, profile.featureReady("password"))
}

func TestClosedProfileAndRedisSelection(t *testing.T) {
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}, policy: settingsdomain.Snapshot{Version: 1}, observedAt: time.Now()}
	require.True(t, profile.Readiness().Ready)
	require.Empty(t, profile.RoutePlan())
	policy := settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Telegram: true}, PasswordEmailVerification: settingsdomain.VerificationOptional}
	require.False(t, profileNeedsRedis(ProjectProfileConfig{}, policy))
	require.False(t, profileNeedsRedis(ProjectProfileConfig{Tokens: &ProjectTokenConfig{Enabled: true}}, policy))
	require.True(t, profileNeedsRedis(ProjectProfileConfig{BrowserEnabled: true}, policy))
	require.False(t, profile.needsProfileVerification(ProjectProfileConfig{BrowserEnabled: true}))
	profile.policy.Policy = policy
	require.False(t, profile.needsProfileVerification(ProjectProfileConfig{BrowserEnabled: true}))
	profile.policy.Policy.Methods.Password = true
	require.True(t, profile.needsProfileVerification(ProjectProfileConfig{BrowserEnabled: true}))
	profile.policy.Policy.PasswordEmailVerification = settingsdomain.VerificationDisabled
	require.False(t, profile.needsProfileVerification(ProjectProfileConfig{BrowserEnabled: true}))
}

func TestProfileRejectsInconsistentBrowserSessionPolicies(t *testing.T) {
	profile := &ProjectProfile{states: map[string]ProjectFeatureState{}, password: &ProjectPassword{cfg: ProjectPasswordConfig{Session: sessionservice.Config{SessionTTL: time.Hour}}}, google: &ProjectOIDC{cfg: ProjectOIDCConfig{Provider: "google", Session: sessionservice.Config{SessionTTL: 2 * time.Hour}}}}
	profile.state("password", "")
	profile.state("google", "")
	profile.bindProfileMFA("")
	require.Nil(t, profile.password)
	require.Nil(t, profile.google)
	require.False(t, profile.featureReady("password"))
	require.False(t, profile.featureReady("google"))
	require.Empty(t, profile.RoutePlan())
}
