package settingshttp

import (
	"net/http"
)

// @Summary Read project email MFA policy
// @Description Requires current project auth.settings.manage permission. Reads saved allowed/version; readiness is a server capability, not a client field.
// @Tags Auth settings
// @Produce json
// @Success 200 {object} EmailMFASettingsResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @ID getAdminAuthSettingsMfaEmail
// @Router /api/v1/admin/auth/settings/mfa/email [get]
func (h *EmailMFAHandler) Read(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := Principal(w, r)
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
