package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Start protected TOTP replacement
// @Description Requires fresh primary and MFA proofs. Primary is password, or opt-in verified-email proof for an external-only account. The current factor remains usable until confirmation. Replacement cannot use an ordinary enrollment token.
// @Tags MFA
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} EnrollmentResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/totp/replacement [post]
func (h *Handler) StartReplacement(w http.ResponseWriter, r *http.Request) {
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	result, err := h.management.StartReplacement(r.Context(), proof)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, EnrollmentResponse{Token: result.Token, Secret: result.Secret, URI: result.URI, ExpiresAt: result.ExpiresAt})
}
