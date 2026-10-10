package http

import "net/http"

// @Summary Revoke one own active session
// @Description Foreign, unknown and inactive sessions share 404. Revoking current session also clears the cookie. Requires an allowed Origin.
// @Tags Session
// @Param Origin header string true "Exact HTTPS origin from AUTH_ALLOWED_ORIGINS"
// @Param id path string true "Public session UUID"
// @Success 204
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/sessions/{id} [delete]
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request, id string) {
	auth, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if err := h.service.Revoke(r.Context(), auth.UserID, auth.TokenHash, id); err != nil {
		h.respondError(w, r, "revoke session", err)
		return
	}
	if id == auth.SessionID {
		ClearSessionCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}
