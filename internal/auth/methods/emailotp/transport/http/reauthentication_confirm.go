package http

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailProofResponse struct {
	VerifiedAt time.Time `json:"verifiedAt"`
} // @name emailotp_http.EmailProofResponse

// @Summary Confirm an email proof for MFA management
// @Description Same owner/session/version and one-time flow cookie; rotates the existing session token atomically without extending lifetime. Grants a five-minute email proof, not password proof, MFA proof or administrative permissions. Existing MFA is still required to replace or disable a factor.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body ConfirmCodeRequest true "Eight-digit email code"
// @Success 200 {object} EmailProofResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/reauthenticate/email/confirm [post]
func (h *Handler) ConfirmReauthentication(w http.ResponseWriter, r *http.Request) {
	proof, ok := reauthenticationProof(w, r)
	if !ok {
		return
	}
	var input ConfirmCodeRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	cookies := r.CookiesNamed(reauthenticationCookie)
	if len(cookies) != 1 {
		h.respondError(w, r, domain.ErrInvalidCode)
		return
	}
	result, err := h.service.ConfirmReauthentication(r.Context(), service.ReauthenticationInput{
		Proof: proof, Code: input.Code, Binding: cookies[0].Value, IP: httpx.IP(r),
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	setNamedFlowCookie(w, reauthenticationCookie, "", time.Unix(1, 0))
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, EmailProofResponse{VerifiedAt: result.VerifiedAt})
}
