package mfahttp

import (
	"net/http"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Disable TOTP for the current account
// @Description Requires fresh password and MFA proofs. Administrative-role policy cannot be bypassed. Removes recovery codes, raises auth_version and revokes all sessions atomically.
// @Tags MFA
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} StatusResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse "codes: invalid_origin, fresh_auth_required, mfa_required_by_policy"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/totp [delete]
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	if err := h.management.Disable(r.Context(), proof); err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}
