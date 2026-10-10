package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Revoke current session and clear browser cookie
// @Description Missing or invalid sessions return 401 and clear the stale cookie. Dependency failures do not clear it. Requires an allowed Origin.
// @Tags Session
// @Param Origin header string true "Exact HTTPS origin from AUTH_ALLOWED_ORIGINS"
// @Success 204
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/logout [post]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	auth, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if err := h.service.Revoke(r.Context(), auth.UserID, auth.TokenHash, auth.SessionID); err != nil {
		if httpx.MapError(err, managementErrors, dependencyFailure).Status == 401 {
			ClearSessionCookie(w)
		}
		h.respondError(w, r, "logout", err)
		return
	}
	ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
