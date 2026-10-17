package router

import "github.com/go-chi/chi/v5"

func administrativeLoginRoutes(r chi.Router, h Handlers) {
	if h.Config == nil || !h.Config.MFA.Enabled || h.PasswordHandler == nil || h.MFA == nil {
		return
	}
	r.With(browserProtection(h)).Post("/admin/auth/login/email", h.PasswordHandler.LoginAdministrator)
}

func mfaRoutes(r chi.Router, h Handlers) {
	if h.MFA == nil || h.Config == nil || !h.Config.MFA.Enabled {
		return
	}
	r.Post("/mfa/login/complete", h.MFA.CompleteLogin)
	r.Post("/mfa/login/enrollment", h.MFA.StartLoginEnrollment)
	r.Post("/mfa/login/enrollment/confirm", h.MFA.ConfirmLoginEnrollment)
	if h.Config.MFA.RecoveryEnabled {
		r.Post("/mfa/recovery/start", h.MFA.StartRecovery)
		r.Post("/mfa/recovery/complete", h.MFA.CompleteRecovery)
	}
	owner := r.With(h.Middleware.NoRefreshAuth)
	if h.EmailOTP != nil && h.Config.EmailOTP.ReauthenticationEnabled {
		owner.Post("/reauthenticate/email/request", h.EmailOTP.RequestReauthentication)
		owner.Post("/reauthenticate/email/confirm", h.EmailOTP.ConfirmReauthentication)
	}
	owner.Post("/mfa/totp/enrollment", h.MFA.StartEnrollment)
	owner.Post("/mfa/totp/enrollment/confirm", h.MFA.ConfirmEnrollment)
	owner.Post("/mfa/step-up", h.MFA.StepUp)
	owner.Delete("/mfa/totp", h.MFA.Disable)
	owner.Post("/mfa/recovery-codes/regenerate", h.MFA.RegenerateRecovery)
	owner.Post("/mfa/totp/replacement", h.MFA.StartReplacement)
	owner.Post("/mfa/totp/replacement/confirm", h.MFA.ConfirmReplacement)
}
