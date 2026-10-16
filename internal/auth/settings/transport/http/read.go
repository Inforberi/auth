package http

import "net/http"

// @Summary Read authentication settings
// @Description Requires a live session and auth.settings.manage. availableMethods describes adapters on this instance only. No secrets are returned; does not refresh the session.
// @Tags Auth settings
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} SettingsResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings [get]
func (h *Handler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	snapshot, err := h.service.Read(r.Context(), actor)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, snapshot)
}
