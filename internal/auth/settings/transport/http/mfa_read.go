package http

import "net/http"

// @Summary Read realm MFA policy
// @Description Requires a live browser session and allowed HTTPS Origin. Local endpoint requires auth.settings.manage; platform endpoint uses independent platform.project_settings.manage authority. No fresh proof is required for reading. Policy applies only to this realm database.
// @Tags MFA settings
// @Produce json
// @Success 200 {object} MFASettingsResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/mfa [get]
// @Router /api/v1/platform/settings/mfa [get]
func (h *MFAHandler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	result, err := h.service.Read(r.Context(), actor)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
