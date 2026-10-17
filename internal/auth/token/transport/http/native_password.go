package http

import (
	"net/http"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type NativePasswordRequest struct {
	Email    string                       `json:"email" binding:"required"`
	Password string                       `json:"password" binding:"required"`
	Audience string                       `json:"audience" binding:"required"`
	Scope    []accessdomain.PermissionKey `json:"scope" binding:"required" swaggertype:"array,string"`
} // @name token_http.NativePasswordRequest

// @Summary Sign in to the native API with a password
// @Description Cookie-free native client only: Origin, Cookie, Authorization and query parameters are rejected. JSON <=8 KiB. Uses current password policy and primary checks. Required MFA/enrollment returns only a bound restricted challenge. No browser session is created. Strict JWT use requires an online authority check at the consumer.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body NativePasswordRequest true "Credentials and resource scope"
// @Success 200 {object} NativeResponse
// @Success 202 {object} NativeChallengeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/native/password/login [post]
func (h *NativeHandler) Password(w http.ResponseWriter, r *http.Request) {
	var input NativePasswordRequest
	if !decodeNative(w, r, &input, []string{"email", "password", "audience", "scope"}) {
		return
	}
	result, err := h.services.Password.Login(r.Context(), service.NativePasswordInput{Email: input.Email, Password: input.Password, Audience: input.Audience, Scope: input.Scope, IP: httpx.IP(r), UserAgent: r.UserAgent()})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.writeLogin(w, r, result)
}
