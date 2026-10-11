package http

import (
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Unlink Telegram from the current account
// @Description Requires Origin and fresh password proof. A verified permanent password login must remain. Successful unlink increments auth_version and revokes all sessions, including the caller. Unknown ownership is not revealed.
// @Tags Account
// @Param Origin header string true "Allowed browser origin"
// @Success 204
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/telegram/link [delete]
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
