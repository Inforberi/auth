package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProviderUpdateRequest struct {
	ExpectedVersion int64   `json:"expectedVersion" binding:"required"`
	ClientID        *string `json:"clientId" binding:"required"`
	Secret          *string `json:"clientSecret" extensions:"x-nullable"`
} // @name provider_settings_http.UpdateRequest

// @Summary Configure or rotate Google/Telegram client credentials
// @Description Requires auth.settings.manage, fresh password+MFA and expectedVersion. Omitted/null secret preserves it; explicit empty clears only while the method is disabled. Client ID change requires explicit secret, disabled method and no linked identities. Rotation invalidates pending OIDC/MFA/enrollment/recovery proofs, not existing sessions. No external connection under SQL locks.
// @Tags Provider settings
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param provider path string true "Provider" Enums(google,telegram)
// @Param body body ProviderUpdateRequest true "client ID, expectedVersion and optional new secret"
// @Success 200 {object} ProviderResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse "provider_settings_conflict, provider_client_bound, auth_method_not_ready"
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/providers/{provider} [post]
func (h *ProviderHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input ProviderUpdateRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil || input.ClientID == nil {
		httpx.Error(w, 400, "invalid_json", "complete provider settings required")
		return
	}
	result, err := h.service.Update(r.Context(), service.ProviderUpdateInput{Actor: actor, Provider: providerName(r), ClientID: *input.ClientID, ExpectedVersion: input.ExpectedVersion, Secret: input.Secret})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
