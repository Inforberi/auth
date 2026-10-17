package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ConfirmLoginEnrollmentRequest struct {
	Challenge string `json:"challenge"`
	Token     string `json:"token"`
	Code      string `json:"code"`
}

// @Summary Confirm mandatory TOTP enrollment during login
// @Description Requires the primary challenge, browser binding, enrollment token and first TOTP. Commits the factor, recovery codes, auth_version and revocation atomically; returns codes once. Creates no session: sign in again with primary plus MFA.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body ConfirmLoginEnrollmentRequest true "Challenge, enrollment token and first code"
// @Success 200 {object} RecoveryCodesResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/login/enrollment/confirm [post]
func (h *Handler) ConfirmLoginEnrollment(w http.ResponseWriter, r *http.Request) {
	var input ConfirmLoginEnrollmentRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.login.ConfirmRequiredEnrollment(r.Context(), service.ConfirmLoginEnrollmentInput{
		LoginEnrollmentInput: service.LoginEnrollmentInput{Challenge: input.Challenge, Binding: loginBinding(r), IP: httpx.IP(r)}, Token: input.Token, Code: input.Code,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	clearLoginCookie(w)
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, RecoveryCodesResponse{Codes: result.Codes})
}
