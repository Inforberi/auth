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
	}
	add("mfa", "browser", "POST", "/api/v1/auth/mfa/login/complete", "/api/v1/auth/mfa/login/enrollment", "/api/v1/auth/mfa/login/enrollment/confirm")
	add("tokens", "public_keys", "GET", "/.well-known/jwks.json")
	add("tokens", "public_keys", "HEAD", "/.well-known/jwks.json")
	add("exchange", "session_no_refresh", "POST", "/api/v1/auth/token/exchange")
	add("sessions", "session", "GET", "/api/v1/auth/me", "/api/v1/auth/sessions")
	add("sessions", "session_logout", "POST", "/api/v1/auth/logout")
	add("sessions", "session_no_refresh", "POST", "/api/v1/auth/logout-all", "/api/v1/auth/session/activity", "/api/v1/auth/session/rotate")
	add("sessions", "session_no_refresh", "DELETE", "/api/v1/auth/sessions/{id}")
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
