package auth

// ProjectRoute is a backend-ready route plan, never an authorization decision or a mounted handler.
type ProjectRoute struct {
	Feature    string `json:"feature"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Protection string `json:"protection"`
}

func (p *ProjectProfile) RoutePlan() []ProjectRoute {
	routes := make([]ProjectRoute, 0, 32)
	add := func(feature, protection, method string, paths ...string) {
		if p.featureReady(feature) {
			for _, path := range paths {
				routes = append(routes, ProjectRoute{Feature: feature, Method: method, Path: path, Protection: protection})
			}
		}
	}
	add("password", "browser", "POST", "/api/v1/auth/login/email")
	add("password", "session_no_refresh", "POST", "/api/v1/auth/change-password", "/api/v1/auth/reauthenticate/password")
	add("temporary_password", "browser", "POST", "/api/v1/auth/temporary-password/login", "/api/v1/auth/temporary-password/complete")
	add("registration", "browser", "POST", "/api/v1/auth/register/email")
	add("verification", "browser", "POST", "/api/v1/auth/email/resend", "/api/v1/auth/email/verify")
	add("recovery", "browser", "POST", "/api/v1/auth/forgot-password", "/api/v1/auth/reset-password")
	add("emailotp", "browser", "POST", "/api/v1/auth/email-otp/request", "/api/v1/auth/email-otp/confirm")
	add("reauthentication", "session_no_refresh", "POST", "/api/v1/auth/reauthenticate/email/request", "/api/v1/auth/reauthenticate/email/confirm")
	for _, name := range []string{"google", "telegram"} {
		add(name, "browser", "POST", "/api/v1/auth/"+name+"/start")
		add(name, "callback", "GET", "/api/v1/auth/"+name+"/callback")
		add(name, "session_no_refresh", "POST", "/api/v1/auth/"+name+"/link")
		add(name, "session_no_refresh", "DELETE", "/api/v1/auth/"+name+"/link")
	}
	add("mfa", "browser", "POST", "/api/v1/auth/mfa/login/complete", "/api/v1/auth/mfa/login/enrollment", "/api/v1/auth/mfa/login/enrollment/confirm")
	add("mfa_management", "session_no_refresh", "GET", "/api/v1/auth/mfa/status")
	add("mfa_management", "session_no_refresh", "POST", "/api/v1/auth/mfa/totp/enrollment", "/api/v1/auth/mfa/totp/enrollment/confirm", "/api/v1/auth/mfa/step-up", "/api/v1/auth/mfa/recovery-codes/regenerate", "/api/v1/auth/mfa/totp/replacement", "/api/v1/auth/mfa/totp/replacement/confirm")
	add("mfa_management", "session_no_refresh", "DELETE", "/api/v1/auth/mfa/totp")
	add("tokens", "public_keys", "GET", "/.well-known/jwks.json")
	add("tokens", "public_keys", "HEAD", "/.well-known/jwks.json")
	add("exchange", "session_no_refresh", "POST", "/api/v1/auth/token/exchange")
	add("sessions", "session", "GET", "/api/v1/auth/me", "/api/v1/auth/sessions")
	add("sessions", "session_logout", "POST", "/api/v1/auth/logout")
	add("sessions", "session_no_refresh", "POST", "/api/v1/auth/logout-all", "/api/v1/auth/session/activity", "/api/v1/auth/session/rotate")
	add("sessions", "session_no_refresh", "DELETE", "/api/v1/auth/sessions/{id}")
	add("provisioning", "session_no_refresh", "POST", "/api/v1/admin/users", "/api/v1/admin/users/{id}/invitation")
	add("invitation_activation", "browser", "POST", "/api/v1/auth/invitations/activate")
	add("temporary_password_admin", "session_no_refresh", "POST", "/api/v1/admin/users/temporary-password", "/api/v1/admin/users/{id}/temporary-password")
	add("retention_settings_read", "session_no_refresh", "GET", "/api/v1/admin/auth/settings/retention")
	add("retention_settings_write", "session_no_refresh", "POST", "/api/v1/admin/auth/settings/retention")
	add("provider_settings_read", "session_no_refresh", "GET", "/api/v1/admin/auth/settings/providers/{provider}")
	add("provider_settings_write", "session_no_refresh", "POST", "/api/v1/admin/auth/settings/providers/{provider}")
	add("smtp_settings_read", "session_no_refresh", "GET", "/api/v1/admin/auth/settings/smtp")
	add("smtp_settings_write", "session_no_refresh", "POST", "/api/v1/admin/auth/settings/smtp", "/api/v1/admin/auth/settings/smtp/test")
	add("auth_settings_read", "session_no_refresh", "GET", "/api/v1/admin/auth/settings")
	add("auth_settings_write", "session_no_refresh", "POST", "/api/v1/admin/auth/settings")
	add("access_read", "session_no_refresh", "GET", "/api/v1/auth/access", "/api/v1/admin/permissions", "/api/v1/admin/roles", "/api/v1/admin/roles/{id}", "/api/v1/admin/users/{id}/access")
	add("access_write", "session_no_refresh", "POST", "/api/v1/admin/roles", "/api/v1/admin/roles/{id}", "/api/v1/admin/users/{id}/roles/{roleId}", "/api/v1/admin/users/{id}/administrator")
	add("access_write", "session_no_refresh", "DELETE", "/api/v1/admin/users/{id}/roles/{roleId}", "/api/v1/admin/users/{id}/administrator")
	add("user_lifecycle", "session_no_refresh", "POST", "/api/v1/admin/users/{id}/status")
	add("user_lifecycle", "session_no_refresh", "DELETE", "/api/v1/admin/users/{id}")
	add("user_directory", "session_no_refresh", "GET", "/api/v1/admin/users", "/api/v1/admin/users/{id}")
	add("email_binding", "session_no_refresh", "POST", "/api/v1/admin/users/{id}/email-binding")
	add("email_binding_confirmation", "session_no_refresh", "POST", "/api/v1/auth/email/binding/confirm")
	add("email_change", "session_no_refresh", "POST", "/api/v1/auth/email/change")
	add("email_change_protection", "browser", "POST", "/api/v1/auth/email/change/confirm", "/api/v1/auth/email/change/report", "/api/v1/auth/email/change/recover")
	for _, method := range []string{"POST", "OPTIONS"} {
		add("native_password", "native", method, "/api/v1/auth/native/password/login")
		add("native_email", "native", method, "/api/v1/auth/native/email/request", "/api/v1/auth/native/email/confirm")
		add("native_mfa", "native", method, "/api/v1/auth/native/mfa/complete", "/api/v1/auth/native/mfa/enrollment", "/api/v1/auth/native/mfa/enrollment/confirm")
		add("refresh", "native", method, "/api/v1/auth/token/refresh")
		add("logout", "native", method, "/api/v1/auth/token/logout")
		add("introspection", "service", method, "/api/v1/internal/auth/token/introspect")
	}
	return routes
}
