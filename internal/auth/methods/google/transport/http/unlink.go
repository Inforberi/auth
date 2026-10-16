package http

import (
	"net/http"
)

// @Summary Unlink Google from the current account
// @Description Requires Origin and fresh password proof. A verified permanent password login must remain. Successful unlink increments auth_version and revokes all sessions, including the caller. Unknown ownership is not revealed.
// @Tags Account
// @Param Origin header string true "Allowed browser origin"
// @Success 204
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse "code: method_disabled"
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/google/link [delete]
func (h *Handler) Unlink(w http.ResponseWriter, r *http.Request) { h.Handler.Unlink(w, r) }
