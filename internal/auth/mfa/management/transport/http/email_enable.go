package mfamanagementhttp

import (
	"net/http"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Enable the proved email MFA channel
// @Description Current owner, fresh password/channel possession and current factor proofs required. Email-only administrative factor is unsupported: enroll TOTP first. Atomically binds the channel, audits and revokes old credentials; no new session.
// @Tags MFA
// @Produce json
// @Success 200 {object} mfahttp.StatusResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/email [post]
func (h *EmailHandler) EnableEmailFactor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := mfahttp.ActionProof(w, r)
	if !ok {
		return
	}
	if err := h.factors.Enable(r.Context(), proof); err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, mfahttp.StatusResponse{Status: "ok"})
}
