package settingsretentionhttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

// @Summary Read saved data retention periods
// @Description Requires a live session, allowed HTTPS Origin and auth.settings.manage. No fresh proof is required for reading. Durations are in days; worker batch and interval remain deployment configuration.
// @Tags Retention settings
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} RetentionResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @ID getAdminAuthSettingsRetention
// @Router /api/v1/admin/auth/settings/retention [get]
func (h *RetentionHandler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := settingshttp.Principal(w, r)
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
