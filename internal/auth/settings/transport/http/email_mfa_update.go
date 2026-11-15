package settingshttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailMFAUpdateRequest struct {
	ExpectedVersion int64 `json:"expectedVersion"`
	Allowed         *bool `json:"allowed"`
} // @name mfa_settings_http.EmailUpdateRequest

// @Summary Update project email MFA policy
// @Description Requires fresh administrative proofs, current permission and optimistic version. Enabling requires a complete project runtime; disabling is rejected while bindings exist. Shares the policy version with MFA mode.
// @Tags Auth settings
// @Produce json
// @Accept json
// @Param body body EmailMFAUpdateRequest true "request"
// @Success 200 {object} EmailMFASettingsResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @ID postAdminAuthSettingsMfaEmail
// @Router /api/v1/admin/auth/settings/mfa/email [post]
func (h *EmailMFAHandler) Update(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := Principal(w, r)
	if !ok {
		return
	}
	var input EmailMFAUpdateRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Allowed == nil {
		httpx.Error(w, 400, "invalid_json", "complete email MFA configuration required")
		return
	}
	result, err := h.service.Update(r.Context(), service.EmailMFAUpdate{Actor: actor, ExpectedVersion: input.ExpectedVersion, Allowed: *input.Allowed})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
