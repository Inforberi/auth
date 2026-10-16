package http

import (
	"net/http"
)

// @Summary Start linking Telegram to the current account
// @Description Requires current session, exact Origin, verified email with permanent password and recent password reauthentication. Flow binds UUID and session hash; callback does not create a session or user. One identity per provider per account.
// @Tags Account
// @Produce json
// @Param Origin header string true "Allowed browser origin"
// @Success 200 {object} StartResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse "code: method_disabled"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/telegram/link [post]
func (h *Handler) StartLink(w http.ResponseWriter, r *http.Request) { h.Handler.StartLink(w, r) }
