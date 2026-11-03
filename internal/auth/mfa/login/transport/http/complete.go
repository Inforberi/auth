package mfaloginhttp

import (
	"net/http"

	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CompleteLoginRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
	Recovery  bool   `json:"recovery"`
} // @name mfa_http.CompleteLoginRequest

// @Summary Complete login with a second factor
// @Description Requires the same browser binding cookie and allowed Origin. Consumes the selected TOTP/recovery or Telegram code and challenge atomically with SQL session issuance. No client UUID, auth version or MFA timestamp is accepted.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body CompleteLoginRequest true "challenge and second factor"
// @Success 200 {object} mfahttp.StatusResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_mfa"
// @Failure 403 {object} httpx.ErrorResponse "codes: invalid_origin, email_not_verified"
// @Failure 404 {object} httpx.ErrorResponse "code: method_disabled"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/mfa/login/complete [post]
func (h *Handler) CompleteLogin(w http.ResponseWriter, r *http.Request) {
	var input CompleteLoginRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.login.Complete(r.Context(), mfalogin.CompleteLoginInput{Token: input.Challenge, Binding: LoginBinding(r), Code: input.Code, Recovery: input.Recovery, UserAgent: httpx.UserAgent(r), IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	ClearLoginCookie(w)
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, mfahttp.StatusResponse{Status: "ok"})
}
