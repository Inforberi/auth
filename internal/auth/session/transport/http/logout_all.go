package http

import "net/http"

// @Summary Revoke all own sessions including current and clear browser cookie
// @Description Requires an allowed Origin. Auth version increment prevents stale in-flight issuance.
// @Tags Session
// @Param Origin header string true "Exact HTTPS origin from AUTH_ALLOWED_ORIGINS"
// @Success 204
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/logout-all [post]
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	auth, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if err := h.service.LogoutAll(r.Context(), auth.UserID, auth.TokenHash); err != nil {
		h.respondError(w, r, "logout all", err)
		return
	}
	ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
