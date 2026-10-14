package mfahttp

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

const LoginCookie = "__Host-mfa-login"

type ChallengeResponse struct {
	Status    string    `json:"status"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name mfa_http.ChallengeResponse

func RespondChallenge(w http.ResponseWriter, challenge *service.LoginChallenge) {
	sessionhttp.ClearSessionCookie(w)
	http.SetCookie(w, &http.Cookie{Name: LoginCookie, Value: challenge.Binding, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: challenge.ExpiresAt})
	httpx.JSON(w, 202, ChallengeResponse{Status: "mfa_required", Challenge: challenge.Token, ExpiresAt: challenge.ExpiresAt})
}

type CompleteLoginRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
	Recovery  bool   `json:"recovery"`
} // @name mfa_http.CompleteLoginRequest

// @Summary Complete login with a second factor
// @Description Requires the same browser binding cookie and allowed Origin. Consumes TOTP/recovery and challenge atomically with SQL session issuance. No client UUID, auth version or MFA timestamp is accepted.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body CompleteLoginRequest true "challenge and second factor"
// @Success 200 {object} StatusResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_mfa"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/mfa/login/complete [post]
func (h *Handler) CompleteLogin(w http.ResponseWriter, r *http.Request) {
	var input CompleteLoginRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.login.Complete(r.Context(), service.CompleteLoginInput{Token: input.Challenge, Binding: loginBinding(r), Code: input.Code, Recovery: input.Recovery, UserAgent: httpx.UserAgent(r), IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	clearLoginCookie(w)
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}

func loginBinding(r *http.Request) string {
	if cookies := r.CookiesNamed(LoginCookie); len(cookies) == 1 {
		return cookies[0].Value
	}
	return ""
}

func clearLoginCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: LoginCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
