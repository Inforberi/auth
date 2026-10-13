package mfahttp

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EnrollmentResponse struct {
	Token     string    `json:"token"`
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name mfa_http.EnrollmentResponse

// @Summary Start TOTP enrollment
// @Description Requires an active session and password reauthentication within five minutes. Returns the secret once in a no-store owner response. Does not enable MFA before confirmation.
// @Tags MFA
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} EnrollmentResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse "codes: invalid_origin, fresh_auth_required"
// @Failure 409 {object} httpx.ErrorResponse "code: mfa_conflict"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/totp/enrollment [post]
func (h *Handler) StartEnrollment(w http.ResponseWriter, r *http.Request) {
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	result, err := h.management.StartEnrollment(r.Context(), proof)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, EnrollmentResponse{Token: result.Token, Secret: result.Secret, URI: result.URI, ExpiresAt: result.ExpiresAt})
}
