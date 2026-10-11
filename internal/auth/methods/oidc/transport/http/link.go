package oidchttp

import (
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (h *Handler) StartLink(w http.ResponseWriter, r *http.Request) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		h.respondError(w, r, accountdomain.ErrFreshAuthRequired)
		return
	}
	started, err := h.service.StartLink(r.Context(), auth.UserID, auth.TokenHash, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.setFlowCookie(w, started.Binding)
	httpx.JSON(w, 200, StartResponse{AuthorizationURL: started.URL})
}
