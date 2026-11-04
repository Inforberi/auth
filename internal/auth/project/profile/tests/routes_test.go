package profile_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestProfileRoutesExcludeUnavailableAndDefendReturnedSnapshots(t *testing.T) {
	states := map[string]runtimeprofile.ProjectFeatureState{}
	states["password"] = runtimeprofile.ProjectFeatureState{Feature: "password", Ready: false, Reason: "missing_configuration"}
	states["google"] = runtimeprofile.ProjectFeatureState{Feature: "google", Ready: true}
	states["native_email"] = runtimeprofile.ProjectFeatureState{Feature: "native_email", Ready: false, Reason: "delivery_not_running"}
	profile := runtimeprofile.New(runtimeprofile.Definition{States: states})
	report := profile.Readiness()
	require.False(t, report.Ready)
	routes := profile.RoutePlan()
	require.Len(t, routes, 4)
	require.Equal(t, runtimeprofile.ProjectRoute{Feature: "google", Method: "POST", Path: "/api/v1/auth/google/start", Protection: "browser"}, routes[0])
	require.Equal(t, "callback", routes[1].Protection)
	require.Equal(t, "POST", routes[2].Method)
	require.Equal(t, "DELETE", routes[3].Method)
	require.Equal(t, "/api/v1/auth/google/link", routes[2].Path)
	require.Equal(t, routes[2].Path, routes[3].Path)
	require.Equal(t, "session_no_refresh", routes[2].Protection)
	require.Equal(t, routes[2].Protection, routes[3].Protection)
	routes[0].Path = "/untrusted"
	report.Features[2].Ready = true
	require.NotEqual(t, "/untrusted", profile.RoutePlan()[0].Path)
	require.False(t, profile.Readiness().Features[2].Ready)
}

func TestProjectEmailManagementRouteProtections(t *testing.T) {
	states := map[string]runtimeprofile.ProjectFeatureState{}
	states["email_binding"] = runtimeprofile.ProjectFeatureState{Feature: "email_binding", Ready: true}
	states["email_binding_confirmation"] = runtimeprofile.ProjectFeatureState{Feature: "email_binding_confirmation", Ready: true}
	states["email_change"] = runtimeprofile.ProjectFeatureState{Feature: "email_change", Ready: true}
	states["email_change_protection"] = runtimeprofile.ProjectFeatureState{Feature: "email_change_protection", Ready: true}
	want := map[string]string{
		"/api/v1/admin/users/{id}/email-binding": "session_no_refresh",
		"/api/v1/auth/email/binding/confirm":     "session_no_refresh",
		"/api/v1/auth/email/change":              "session_no_refresh",
		"/api/v1/auth/email/change/confirm":      "browser",
		"/api/v1/auth/email/change/report":       "browser",
		"/api/v1/auth/email/change/recover":      "browser",
	}
	require.Len(t, runtimeprofile.New(runtimeprofile.Definition{States: states}).RoutePlan(), len(want))
	for _, route := range runtimeprofile.New(runtimeprofile.Definition{States: states}).RoutePlan() {
		require.Equal(t, "POST", route.Method)
		require.Equal(t, want[route.Path], route.Protection)
	}
}

func TestProjectMFAManagementRouteProtections(t *testing.T) {
	states := map[string]runtimeprofile.ProjectFeatureState{}
	states["mfa_management"] = runtimeprofile.ProjectFeatureState{Feature: "mfa_management", Ready: false, Reason: "redis_unavailable"}
	require.Empty(t, runtimeprofile.New(runtimeprofile.Definition{States: states}).RoutePlan())
	states["mfa_management"] = runtimeprofile.ProjectFeatureState{Feature: "mfa_management", Ready: true}
	routes := runtimeprofile.New(runtimeprofile.Definition{States: states}).RoutePlan()
	require.Len(t, routes, 8)
	methods := map[string]int{}
	for _, route := range routes {
		require.Equal(t, "session_no_refresh", route.Protection)
		methods[route.Method]++
	}
	require.Equal(t, map[string]int{"GET": 1, "POST": 6, "DELETE": 1}, methods)
}

func TestProjectProvisioningRouteProtection(t *testing.T) {
	states := map[string]runtimeprofile.ProjectFeatureState{}
	for _, feature := range []string{"provisioning", "invitation_activation", "temporary_password_admin", "user_directory"} {
		states[feature] = runtimeprofile.ProjectFeatureState{Feature: feature, Ready: true}
	}
	routes := runtimeprofile.New(runtimeprofile.Definition{States: states}).RoutePlan()
	require.Len(t, routes, 7)
	for _, route := range routes {
		if route.Feature == "invitation_activation" {
			require.Equal(t, "browser", route.Protection)
		} else {
			require.Equal(t, "session_no_refresh", route.Protection)
		}
	}
}

func TestProjectMFARecoveryRouteProtections(t *testing.T) {
	states := map[string]runtimeprofile.ProjectFeatureState{}
	states["mfa_recovery"] = runtimeprofile.ProjectFeatureState{Feature: "mfa_recovery", Ready: true}
	routes := runtimeprofile.New(runtimeprofile.Definition{States: states}).RoutePlan()
	require.Len(t, routes, 2)
	for _, route := range routes {
		require.Equal(t, "POST", route.Method)
		require.Equal(t, "browser", route.Protection, "recovery uses challenge binding and Origin, not an authenticated session")
	}
}

func TestClosedProfileReadiness(t *testing.T) {
	p := runtimeprofile.New(runtimeprofile.Definition{Policy: settingsdomain.Snapshot{Version: 1}, ObservedAt: time.Now()})
	require.True(t, p.Readiness().Ready)
	require.Empty(t, p.RoutePlan())
}

func TestSettingsAccessAndUserRoutePlans(t *testing.T) {
	for _, test := range []struct {
		feature string
		methods map[string]int
		paths   []string
	}{
		{"auth_settings_read", map[string]int{"GET": 1}, []string{"/api/v1/admin/auth/settings"}},
		{"auth_settings_write", map[string]int{"POST": 1}, []string{"/api/v1/admin/auth/settings"}},
		{"retention_settings_read", map[string]int{"GET": 1}, []string{"/api/v1/admin/auth/settings/retention"}},
		{"retention_settings_write", map[string]int{"POST": 1}, []string{"/api/v1/admin/auth/settings/retention"}},
		{"provider_settings_read", map[string]int{"GET": 1}, []string{"/api/v1/admin/auth/settings/providers/{provider}"}},
		{"provider_settings_write", map[string]int{"POST": 1}, []string{"/api/v1/admin/auth/settings/providers/{provider}"}},
		{"smtp_settings_read", map[string]int{"GET": 1}, []string{"/api/v1/admin/auth/settings/smtp"}},
		{"smtp_settings_write", map[string]int{"POST": 2}, []string{"/api/v1/admin/auth/settings/smtp", "/api/v1/admin/auth/settings/smtp/test"}},
		{"mfa_settings", map[string]int{"GET": 2, "POST": 2}, []string{"/api/v1/admin/auth/settings/mfa/email", "/api/v1/admin/auth/settings/mfa"}},
		{"access_read", map[string]int{"GET": 5}, []string{"/api/v1/auth/access", "/api/v1/admin/permissions", "/api/v1/admin/roles", "/api/v1/admin/roles/{id}", "/api/v1/admin/users/{id}/access"}},
		{"access_write", map[string]int{"POST": 4, "DELETE": 2}, []string{"/api/v1/admin/roles", "/api/v1/admin/roles/{id}", "/api/v1/admin/users/{id}/roles/{roleId}", "/api/v1/admin/users/{id}/administrator"}},
		{"user_directory", map[string]int{"GET": 2}, []string{"/api/v1/admin/users", "/api/v1/admin/users/{id}"}},
		{"user_lifecycle", map[string]int{"POST": 1, "DELETE": 1}, []string{"/api/v1/admin/users/{id}/status", "/api/v1/admin/users/{id}"}},
	} {
		t.Run(test.feature, func(t *testing.T) {
			states := map[string]runtimeprofile.ProjectFeatureState{test.feature: {Feature: test.feature, Ready: true}}
			routes := runtimeprofile.New(runtimeprofile.Definition{States: states}).RoutePlan()
			methods := map[string]int{}
			paths := map[string]bool{}
			for _, route := range routes {
				require.Equal(t, "session_no_refresh", route.Protection)
				require.Contains(t, test.paths, route.Path)
				paths[route.Path] = true
				methods[route.Method]++
			}
			require.Len(t, paths, len(test.paths))
			require.Equal(t, test.methods, methods)
			states[test.feature] = runtimeprofile.ProjectFeatureState{Feature: test.feature, Reason: "unavailable"}
			require.Empty(t, runtimeprofile.New(runtimeprofile.Definition{States: states}).RoutePlan())
		})
	}
}

func TestSessionRoutePlanDoesNotRequirePrimaryMethods(t *testing.T) {
	p := runtimeprofile.New(runtimeprofile.Definition{States: map[string]runtimeprofile.ProjectFeatureState{"sessions": {Feature: "sessions", Ready: true}}})
	routes := p.RoutePlan()
	require.Len(t, routes, 7)
	for _, route := range routes {
		require.Equal(t, "sessions", route.Feature)
	}
}

func TestEmailMFARouteProtection(t *testing.T) {
	p := runtimeprofile.New(runtimeprofile.Definition{States: map[string]runtimeprofile.ProjectFeatureState{"email_mfa": {Feature: "email_mfa", Ready: true}, "email_mfa_login": {Feature: "email_mfa_login", Ready: true}}})
	for _, route := range p.RoutePlan() {
		if route.Feature == "email_mfa" {
			require.Equal(t, "session_no_refresh", route.Protection)
		} else {
			require.Equal(t, "browser", route.Protection)
		}
	}
}
