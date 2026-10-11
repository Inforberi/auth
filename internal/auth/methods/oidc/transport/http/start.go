package oidchttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type StartResponse struct {
	AuthorizationURL string `json:"authorizationUrl"`
}

func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	started, err := h.service.Start(r.Context(), httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.setFlowCookie(w, started.Binding)
	httpx.JSON(w, 200, StartResponse{AuthorizationURL: started.URL})
}
