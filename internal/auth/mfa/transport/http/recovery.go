package mfahttp

import (
	"net/http"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Regenerate recovery codes
// @Description Requires fresh primary and MFA proofs. Primary is password, or opt-in verified-email proof for an external-only account. Replaces all recovery codes, returns ten new codes once and revokes sessions/pending challenges atomically. TOTP remains enabled.
// @Tags MFA
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} RecoveryCodesResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/recovery-codes/regenerate [post]
func (h *Handler) RegenerateRecovery(w http.ResponseWriter, r *http.Request) {
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	result, err := h.management.RegenerateRecovery(r.Context(), proof)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, RecoveryCodesResponse{Codes: result.Codes})
}
