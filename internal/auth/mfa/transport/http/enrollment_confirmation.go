package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type (
	ConfirmEnrollmentRequest struct {
		Token string `json:"token"`
		Code  string `json:"code"`
	} // @name mfa_http.ConfirmEnrollmentRequest
	RecoveryCodesResponse struct {
		Codes []string `json:"codes"`
	} // @name mfa_http.RecoveryCodesResponse
)

// @Summary Confirm TOTP enrollment
// @Description Consumes the first code, returns ten recovery codes once, raises auth_version and revokes all sessions atomically. Sign in again with MFA; no session is created here.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body ConfirmEnrollmentRequest true "enrollment token and first code"
// @Success 200 {object} RecoveryCodesResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/totp/enrollment/confirm [post]
func (h *Handler) ConfirmEnrollment(w http.ResponseWriter, r *http.Request) {
	var input ConfirmEnrollmentRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	result, err := h.management.ConfirmEnrollment(r.Context(), service.ConfirmInput{Proof: proof, Token: input.Token, Code: input.Code})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, RecoveryCodesResponse{Codes: result.Codes})
}
