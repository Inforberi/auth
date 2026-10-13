package router

import "github.com/go-chi/chi/v5"

func mfaRoutes(r chi.Router, h Handlers) {
	if h.MFA == nil || h.Config == nil || !h.Config.MFA.Enabled {
		return
	}
	r.Post("/mfa/login/complete", h.MFA.CompleteLogin)
	owner := r.With(h.Middleware.NoRefreshAuth)
	owner.Post("/mfa/totp/enrollment", h.MFA.StartEnrollment)
	owner.Post("/mfa/totp/enrollment/confirm", h.MFA.ConfirmEnrollment)
	owner.Post("/mfa/step-up", h.MFA.StepUp)
	owner.Delete("/mfa/totp", h.MFA.Disable)
	owner.Post("/mfa/recovery-codes/regenerate", h.MFA.RegenerateRecovery)
	owner.Post("/mfa/totp/replacement", h.MFA.StartReplacement)
	owner.Post("/mfa/totp/replacement/confirm", h.MFA.ConfirmReplacement)
}
