package mfamanagementhttp

import (
	"net/http"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailPreparationConfirmation struct {
	Binding string `json:"binding"`
	Code    string `json:"code"`
} // @name mfa_http.EmailPreparationConfirmation

// @Summary Confirm email MFA channel possession
// @Description Consumes the dedicated code and rotates the current session verifier without increasing its lifetime or granting strong MFA. Requires allowed Origin and the original owner session proof.
// @Tags MFA
// @Produce json
// @Accept json
// @Param body body EmailPreparationConfirmation true "request"
// @Success 200 {object} mfahttp.StatusResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @ID postAuthMfaEmailPreparationConfirm
// @Router /api/v1/auth/mfa/email/preparation/confirm [post]
func (h *EmailHandler) ConfirmEmailPreparation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := mfahttp.RequestProof(w, r)
	if !ok {
		return
	}
	var input EmailPreparationConfirmation
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.preparation.Confirm(r.Context(), otpservice.EmailPreparationConfirmation{Proof: proof, Binding: input.Binding, Code: input.Code, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, mfahttp.StatusResponse{Status: "ok"})
}
