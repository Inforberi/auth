package router

import "github.com/go-chi/chi/v5"

func publicTokenRoutes(r chi.Router, h Handlers) {
	if h.Tokens == nil || h.Config == nil || !h.Config.JWT.Enabled {
		return
	}
	r.Get("/.well-known/jwks.json", h.Tokens.JWKS)
	r.Head("/.well-known/jwks.json", h.Tokens.JWKS)
}

func tokenExchangeRoutes(r chi.Router, h Handlers) {
	if h.Tokens == nil || h.Config == nil || !h.Config.JWT.Enabled || h.Middleware == nil {
		return
	}
	r.With(h.Middleware.NoRefreshAuth).Post("/token/exchange", h.Tokens.Exchange)
}
