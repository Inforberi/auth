package mfahttp

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailPreparationRequest struct {
	Email string `json:"email"`
} // @name mfa_http.EmailPreparationRequest

type EmailPreparationResponse struct {
	Binding   string    `json:"binding"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name mfa_http.EmailPreparationResponse

// @Summary Prove possession of an email MFA channel
// @Description Requires current owner session, fresh explicit password proof and any currently required MFA proof. Only an owned verified address is accepted. Sends a separate-purpose code; does not enable a factor or create a session.
// @Tags MFA
// @Produce json
// @Accept json
// @Param body body EmailPreparationRequest true "request"
// @Success 202 {object} EmailPreparationResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/email/preparation [post]
func (h *EmailHandler) RequestEmailPreparation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	var input EmailPreparationRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.preparation.Request(r.Context(), proof, input.Email, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 202, EmailPreparationResponse{Binding: result.Binding, ExpiresAt: result.ExpiresAt})
}
