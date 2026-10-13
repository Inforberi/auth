package mfahttp

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type (
	StepUpRequest struct {
		Code     string `json:"code"`
		Recovery bool   `json:"recovery"`
	} // @name mfa_http.StepUpRequest
	StepUpResponse struct {
		VerifiedAt time.Time `json:"verifiedAt"`
	} // @name mfa_http.StepUpResponse
)

// @Summary Confirm a fresh second factor
// @Description Requires fresh password proof, or opt-in verified-email proof for an external-only account, within five minutes. Consumes TOTP/recovery, rotates the current session verifier and records fresh MFA context atomically. Does not extend session lifetime.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body StepUpRequest true "second factor"
// @Success 200 {object} StepUpResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/step-up [post]
func (h *Handler) StepUp(w http.ResponseWriter, r *http.Request) {
	var input StepUpRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	result, err := h.management.StepUp(r.Context(), service.StepUpInput{Proof: proof, Code: input.Code, Recovery: input.Recovery})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, StepUpResponse{VerifiedAt: result.VerifiedAt})
}
