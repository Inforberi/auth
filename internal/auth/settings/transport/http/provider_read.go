package http

import "net/http"

// @Summary Read Google or Telegram client settings without the secret
// @Description Live session, HTTPS Origin and auth.settings.manage; no fresh proof for reading. Presence is not a live provider test. Redirect URI and fixed issuer/endpoints remain deployment configuration.
// @Tags Provider settings
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param provider path string true "Provider" Enums(google,telegram)
// @Success 200 {object} ProviderResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/providers/{provider} [get]
func (h *ProviderHandler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	result, err := h.service.Read(r.Context(), actor, providerName(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
