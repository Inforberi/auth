package router

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

// NewOperator publishes only self-service operator authentication, never project administration.
func NewOperator(h Handlers) (http.Handler, error) {
	if h.Config == nil || !h.Config.Platform.Enabled || h.PasswordHandler == nil || h.MFA == nil || h.Middleware == nil || h.Session == nil || h.Recovery == nil || h.ReadyCheck == nil {
		return nil, errors.New("incomplete operator HTTP profile")
	}
	if err := h.Config.ValidatePlatform(); err != nil {
		return nil, err
	}
	origin, err := url.Parse(h.Config.Platform.Origin)
	if err != nil {
		return nil, err
	}
	r := baseRouter(h)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			// No forwarded-host fallback or plaintext listener for the initial platform profile.
			if r.Host != origin.Host || r.TLS == nil {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	r.Get("/health/live", live)
	r.Get("/health/ready", readiness(h.ReadyCheck))
	r.Route("/api/v1", func(r chi.Router) {
		setupRoutes(r, h)
		administrativeLoginRoutes(r, h)
		r.Route("/auth", func(r chi.Router) {
			r.Use(browserProtection(h))
			r.Post("/forgot-password", h.Recovery.Forgot)
			r.Post("/reset-password", h.Recovery.Reset)
			r.Post("/mfa/login/complete", h.MFA.CompleteLogin)
			sessionRoutes(r, h)
			owner := r.With(h.Middleware.NoRefreshAuth)
			owner.Post("/change-password", h.PasswordHandler.ChangePassword)
			owner.Get("/mfa/status", h.MFA.ReadStatus)
			owner.Post("/mfa/step-up", h.MFA.StepUp)
			owner.Post("/mfa/recovery-codes/regenerate", h.MFA.RegenerateRecovery)
			owner.Post("/mfa/totp/replacement", h.MFA.StartReplacement)
			owner.Post("/mfa/totp/replacement/confirm", h.MFA.ConfirmReplacement)
		})
	})
	return r, nil
}
