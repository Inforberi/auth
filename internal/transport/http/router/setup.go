package router

import "github.com/go-chi/chi/v5"

func setupRoutes(r chi.Router, h Handlers) {
	if h.Setup == nil || h.Config == nil || !h.Config.InitialSetup.Enabled || !h.Config.MFA.Enabled {
		return
	}
	protected := r.With(browserProtection(h))
	protected.Post("/setup/start", h.Setup.Start)
	protected.Post("/setup/complete", h.Setup.Complete)
}
