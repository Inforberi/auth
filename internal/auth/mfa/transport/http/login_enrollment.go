package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type LoginEnrollmentRequest struct {
	Challenge string `json:"challenge"`
}

// @Summary Start mandatory TOTP enrollment during login
// @Description Accepts only an enrollment-required primary challenge with the same browser binding. No full session, account UUID or password is accepted. Secret expires with the existing login challenge; restarting does not extend its deadline.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body LoginEnrollmentRequest true "Primary login challenge"
// @Success 200 {object} EnrollmentResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/login/enrollment [post]
func (h *Handler) StartLoginEnrollment(w http.ResponseWriter, r *http.Request) {
	var input LoginEnrollmentRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.login.StartRequiredEnrollment(r.Context(), service.LoginEnrollmentInput{Challenge: input.Challenge, Binding: loginBinding(r), IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, EnrollmentResponse{Token: result.Token, Secret: result.Secret, URI: result.URI, ExpiresAt: result.ExpiresAt})
}
