package http

import (
	"net/http"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ConfirmEmailBindingRequest struct {
	Code string `json:"code"`
}

// @Summary Confirm the owner's initial email binding
// @Description Requires the target's live session, mailed eight-digit code and fresh MFA if a factor is enrolled. Rechecks the approving administrator's current password/MFA/session/permission in SQL. Atomically creates a verified contact, raises auth_version, revokes all target sessions and records audit. Does not create login authority or merge accounts.
// @Tags Account
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body ConfirmEmailBindingRequest true "Code from the approved email"
// @Success 200 {object} VerificationResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/email/binding/confirm [post]
func (h *EmailBindingHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	auth, ok := bindingOwner(w, r)
	if !ok {
		return
	}
	var input ConfirmEmailBindingRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	err := h.service.Confirm(r.Context(), mfaservice.Proof{UserID: auth.UserID, TokenHash: auth.TokenHash, AuthVersion: auth.AuthVersion}, input.Code, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, VerificationResponse{Status: "ok"})
}
