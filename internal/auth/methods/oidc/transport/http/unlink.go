package oidchttp

import (
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (h *Handler) Unlink(w http.ResponseWriter, r *http.Request) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		h.respondError(w, r, accountdomain.ErrFreshAuthRequired)
		return
	}
	if err := h.service.Unlink(r.Context(), auth.UserID, auth.TokenHash, httpx.IP(r)); err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
