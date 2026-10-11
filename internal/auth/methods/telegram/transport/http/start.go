package http

import (
	"net/http"

	oidchttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/transport/http"
)

type StartResponse = oidchttp.StartResponse

// @Summary Start Telegram OIDC login
// @Description Requires allowed Origin. Sets a browser-bound HttpOnly flow cookie; navigate to authorizationUrl. Disabled by default.
// @Tags Auth
// @Param Origin header string true "Allowed HTTPS origin"
// @Produce json
// @Success 200 {object} oidchttp.StartResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/telegram/start [post]
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) { h.Handler.Start(w, r) }
