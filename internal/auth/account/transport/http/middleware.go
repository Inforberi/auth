package http

import (
	"errors"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (h *Handler) RequireVerified(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := sessionhttp.GetAuthContext(r.Context())
		if !ok {
			httpx.Error(w, 401, "unauthorized", "unauthorized")
			return
		}
		err := h.service.RequireVerified(r.Context(), auth.UserID)
		if errors.Is(err, domain.ErrEmailUnverified) {
			httpx.Error(w, 403, "email_not_verified", "email not verified")
			return
		}
		if err != nil {
			h.respondError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) LimitRegistration(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.service.AllowRegistration(r.Context(), httpx.IP(r)); err != nil {
			h.respondError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}
