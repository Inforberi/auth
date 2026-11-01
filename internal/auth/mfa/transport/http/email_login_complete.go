package mfahttp

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CompleteEmailLoginRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
} // @name mfa_http.CompleteEmailLoginRequest

// CompleteEmailLogin accepts binding only from one HttpOnly cookie, never from JSON or query.
// @Summary Complete browser email second-factor login
// @Description Requires exactly one project binding cookie and the same one-use challenge/code. TOTP, native, foreign, replaced, expired and replayed challenges fail closed. Sets the shared browser session cookie; never returns its token in JSON.
// @Tags MFA
// @Produce json
// @Accept json
// @Param body body CompleteEmailLoginRequest true "request"
// @Success 200 {object} StatusResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/email/login/complete [post]
func (h *EmailHandler) CompleteEmailLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input CompleteEmailLoginRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	cookies := r.CookiesNamed(h.cookieName)
	if len(cookies) != 1 {
		httpx.Error(w, 400, "invalid_mfa", "invalid MFA proof")
		return
	}
	binding := cookies[0].Value
	result, err := h.login.Complete(r.Context(), service.CompleteLoginInput{Token: input.Challenge, Binding: binding, Code: input.Code, UserAgent: httpx.UserAgent(r), IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}
