package http

import (
	"net/http"

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
		if err != nil {
			h.respondError(w, r, err, "require verified email", verifiedErrors)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) LimitRegistration(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.service.AllowRegistration(r.Context(), httpx.IP(r)); err != nil {
			h.respondError(w, r, err, "limit registration", verificationErrors)
			return
		}
		next.ServeHTTP(w, r)
	})
}
