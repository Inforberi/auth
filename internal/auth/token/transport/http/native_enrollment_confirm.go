package http

import (
	"net/http"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type NativeEnrollmentConfirmRequest struct {
	Challenge string `json:"challenge" binding:"required"`
	Binding   string `json:"binding" binding:"required"`
	Token     string `json:"token" binding:"required"`
	Code      string `json:"code" binding:"required"`
} // @name token_http.NativeEnrollmentConfirmRequest

type NativeRecoveryCodesResponse struct {
	Codes []string `json:"codes"`
} // @name token_http.NativeRecoveryCodesResponse

// @Summary Confirm required native TOTP enrollment
// @Description Commits TOTP, recovery codes, version bump and revocation together. Codes returned once. Does not issue tokens: perform a fresh primary login then MFA. Native challenge/binding only; no Origin/Cookie/Authorization/query or cookie mutations.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body NativeEnrollmentConfirmRequest true "Primary challenge, native binding, enrollment token and first TOTP"
// @Success 200 {object} NativeRecoveryCodesResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/native/mfa/enrollment/confirm [post]
func (h *NativeHandler) ConfirmEnrollment(w http.ResponseWriter, r *http.Request) {
	var input NativeEnrollmentConfirmRequest
	if !decodeNative(w, r, &input, []string{"challenge", "binding", "token", "code"}) {
		return
	}
	result, err := h.services.Enrollment.ConfirmNativeRequiredEnrollment(r.Context(), mfaservice.ConfirmLoginEnrollmentInput{
		LoginEnrollmentInput: mfaservice.LoginEnrollmentInput{Challenge: input.Challenge, Binding: input.Binding, IP: httpx.IP(r)}, Token: input.Token, Code: input.Code,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, NativeRecoveryCodesResponse{Codes: result.Codes})
}
