package http

import (
	"net/http"

	emailservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type NativeEmailConfirmRequest struct {
	Binding string `json:"binding" binding:"required"`
	Code    string `json:"code" binding:"required"`
} // @name token_http.NativeEmailConfirmRequest

// @Summary Sign in with a native email code
// @Description Native client only. One-use binding/code, not a browser challenge. Audience/scope come only from stored request. Email code is the primary method, not MFA. If issuance fails after code consumption, request a new code; no retry/grace or intermediate cookie session.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body NativeEmailConfirmRequest true "Native binding and email code"
// @Success 200 {object} NativeResponse
// @Success 202 {object} NativeChallengeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/native/email/confirm [post]
func (h *NativeHandler) EmailConfirm(w http.ResponseWriter, r *http.Request) {
	var input NativeEmailConfirmRequest
	if !decodeNative(w, r, &input, []string{"binding", "code"}) {
		return
	}
	result, err := h.services.Email.Confirm(r.Context(), emailservice.ConfirmInput{Binding: input.Binding, Code: input.Code, IP: httpx.IP(r), UserAgent: r.UserAgent()})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.writeLogin(w, r, result)
}
