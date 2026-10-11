package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type StartResponse struct {
	AuthorizationURL string `json:"authorizationUrl"`
}

// @Summary Start Telegram OIDC login
// @Description Requires allowed Origin. Sets a browser-bound HttpOnly flow cookie; navigate to authorizationUrl. Disabled by default.
// @Tags Auth
// @Param Origin header string true "Allowed HTTPS origin"
// @Produce json
// @Success 200 {object} StartResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/telegram/start [post]
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	started, err := h.service.Start(r.Context(), httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	setFlowCookie(w, started.Binding)
	httpx.JSON(w, 200, StartResponse{AuthorizationURL: started.URL})
}
