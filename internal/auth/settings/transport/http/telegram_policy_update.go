package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Update Telegram MFA policy
// @Description Requires current auth.settings.manage. Mutations require fresh password/strong MFA and expectedVersion. Secrets are never returned.
// @Tags Auth settings
// @Produce json
// @Accept json
// @Param body body TelegramPolicyRequest true "settings"
// @Success 200 {object} TelegramPolicyResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/mfa/telegram [post]
func (h *TelegramHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input TelegramPolicyRequest
	if httpx.DecodeJSON(w, r, &input) != nil || input.Allowed == nil {
		httpx.Error(w, 400, "invalid_json", "allowed and expectedVersion required")
		return
	}
	result, err := h.service.UpdatePolicy(r.Context(), service.TelegramMFAUpdate{Actor: actor, ExpectedVersion: input.ExpectedVersion, Allowed: *input.Allowed})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, TelegramPolicyResponse{Version: result.Version, Allowed: result.Allowed})
}
