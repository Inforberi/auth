package mfamanagementhttp

import (
	"net/http"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Disable personal email MFA
// @Description Requires current primary/factor proofs, allowed Origin and session. Cannot remove the last mandatory factor. Atomically revokes old credentials and audits; disabling project policy alone does not remove bindings.
// @Tags MFA
// @Produce json
// @Success 200 {object} mfahttp.StatusResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/email [delete]
func (h *EmailHandler) DisableEmailFactor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := mfahttp.ActionProof(w, r)
	if !ok {
		return
	}
	if err := h.factors.Disable(r.Context(), proof); err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, mfahttp.StatusResponse{Status: "ok"})
}
