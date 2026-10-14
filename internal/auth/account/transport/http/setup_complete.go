package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type SetupCompleteRequest struct {
	Token     string `json:"token"`
	EmailCode string `json:"emailCode"`
	TOTP      string `json:"totp"`
}
type SetupCompleteResponse struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

// @Summary Complete first administrator setup exactly once
// @Description Consumes installation proof and pending intent with email and TOTP codes. Atomically creates account, verified contact, factor, recovery codes, system grant and durable initialized marker. Returns recovery codes once; does not issue a session. Setup stays closed after restart or loss of administrator.
// @Tags Setup
// @Accept json
// @Produce json
// @Param X-Setup-Token header string true "Installation operator proof"
// @Param body body SetupCompleteRequest true "Setup confirmation"
// @Success 200 {object} SetupCompleteResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/setup/complete [post]
func (h *SetupHandler) Complete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input SetupCompleteRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Complete(r.Context(), service.SetupCompleteInput{OperatorSecret: r.Header.Get("X-Setup-Token"), Token: input.Token, EmailCode: input.EmailCode, TOTP: input.TOTP, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, SetupCompleteResponse{RecoveryCodes: result.RecoveryCodes})
}
