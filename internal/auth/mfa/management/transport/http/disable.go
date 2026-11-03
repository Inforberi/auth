package mfamanagementhttp

import (
	"net/http"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Disable TOTP for the current account
// @Description Requires fresh primary and MFA proofs. Primary is password, or opt-in verified-email proof for an external-only account. Platform assembly always applies administrative realm intent, including operators without local Auth roles. Realm and role requirements cannot be bypassed. Recovery codes are consumed through step-up first. Removes recovery codes, raises auth_version and revokes all sessions atomically.
// @Tags MFA
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} mfahttp.StatusResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse "codes: invalid_origin, fresh_auth_required, mfa_required_by_policy"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/totp [delete]
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	proof, ok := mfahttp.RequestProof(w, r)
	if !ok {
		return
	}
	if err := h.management.Disable(r.Context(), proof); err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, mfahttp.StatusResponse{Status: "ok"})
}
