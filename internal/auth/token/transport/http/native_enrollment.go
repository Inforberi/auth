package http

import (
	"net/http"
	"time"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type NativeEnrollmentRequest struct {
	Challenge string `json:"challenge" binding:"required"`
	Binding   string `json:"binding" binding:"required"`
} // @name token_http.NativeEnrollmentRequest

type NativeEnrollmentResponse struct {
	Token     string    `json:"token"`
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name token_http.NativeEnrollmentResponse

// @Summary Start required native TOTP enrollment
// @Description Only a native enrollment-required primary challenge and its binding. No Origin/Cookie/Authorization/query. Returns the enrollment secret once for setup, no access or refresh credentials. Repeating start does not extend the primary challenge deadline.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body NativeEnrollmentRequest true "Native enrollment-required challenge"
// @Success 200 {object} NativeEnrollmentResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/native/mfa/enrollment [post]
func (h *NativeHandler) StartEnrollment(w http.ResponseWriter, r *http.Request) {
	var input NativeEnrollmentRequest
	if !decodeNative(w, r, &input, []string{"challenge", "binding"}) {
		return
	}
	result, err := h.services.Enrollment.StartNativeRequiredEnrollment(r.Context(), mfaservice.LoginEnrollmentInput{Challenge: input.Challenge, Binding: input.Binding, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, NativeEnrollmentResponse{Token: result.Token, Secret: result.Secret, URI: result.URI, ExpiresAt: result.ExpiresAt})
}
