package http

import (
	"net/http"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type NativeMFARequest struct {
	Challenge string `json:"challenge" binding:"required"`
	Binding   string `json:"binding" binding:"required"`
	Code      string `json:"code" binding:"required"`
	Recovery  bool   `json:"recovery"`
} // @name token_http.NativeMFARequest

// @Summary Complete native MFA login
// @Description Cookie-free native challenge only, never browser/private-admin proof. Recovery defaults to false (TOTP); true selects one recovery code. Factor consumption, session/family issuance and audit commit atomically. Parallel/replayed attempts cannot create independent successors. No Origin/Cookie/Authorization/query.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body NativeMFARequest true "Native challenge, binding and factor"
// @Success 200 {object} NativeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse "method_disabled"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/native/mfa/complete [post]
func (h *NativeHandler) CompleteMFA(w http.ResponseWriter, r *http.Request) {
	var input NativeMFARequest
	if !decodeNative(w, r, &input, []string{"challenge", "binding", "code"}, "recovery") {
		return
	}
	result, err := h.services.MFA.Complete(r.Context(), mfaservice.CompleteLoginInput{Token: input.Challenge, Binding: input.Binding, Code: input.Code, Recovery: input.Recovery, IP: httpx.IP(r), UserAgent: r.UserAgent()})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.writeTokens(w, r, result)
}
