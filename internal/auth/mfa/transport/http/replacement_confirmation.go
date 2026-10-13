package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Confirm protected TOTP replacement
// @Description Requires the unchanged fresh password/MFA session, replacement token and a code from the new factor. Replaces secret/recovery codes, raises auth_version and revokes all sessions atomically.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body ConfirmEnrollmentRequest true "replacement token and new-factor code"
// @Success 200 {object} RecoveryCodesResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/totp/replacement/confirm [post]
func (h *Handler) ConfirmReplacement(w http.ResponseWriter, r *http.Request) {
	var input ConfirmEnrollmentRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	result, err := h.management.ConfirmReplacement(r.Context(), service.ConfirmInput{Proof: proof, Token: input.Token, Code: input.Code})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, RecoveryCodesResponse{Codes: result.Codes})
}
