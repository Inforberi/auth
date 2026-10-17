package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

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

func nativeTokenRoutes(r chi.Router, h Handlers) {
	if h.NativeTokens == nil || h.Config == nil || !h.Config.JWT.Enabled || !h.Config.JWT.NativeEnabled {
		return
	}
	native := r.With(h.NativeTokens.Protect)
	routes := map[string]http.HandlerFunc{
		"/auth/native/password/login":         h.NativeTokens.Password,
		"/auth/native/mfa/complete":           h.NativeTokens.CompleteMFA,
		"/auth/native/mfa/enrollment":         h.NativeTokens.StartEnrollment,
		"/auth/native/mfa/enrollment/confirm": h.NativeTokens.ConfirmEnrollment,
		"/auth/token/refresh":                 h.NativeTokens.Refresh,
		"/auth/token/logout":                  h.NativeTokens.Logout,
	}
	if h.Config.EmailOTP.Enabled {
		routes["/auth/native/email/request"] = h.NativeTokens.EmailRequest
		routes["/auth/native/email/confirm"] = h.NativeTokens.EmailConfirm
	}
	for path, handler := range routes {
		native.Post(path, handler)
		native.Options(path, handler) // Protect rejects preflight before the handler.
	}
}

func introspectionRoutes(r chi.Router, h Handlers) {
	if h.Config == nil || !h.Config.JWT.Enabled || h.Introspection == nil {
		return
	}
	r.Post("/internal/auth/token/introspect", h.Introspection.Inspect)
	r.Options("/internal/auth/token/introspect", h.Introspection.Inspect)
}
