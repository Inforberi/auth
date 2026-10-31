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
func (h *EmailHandler) CompleteEmailLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input CompleteEmailLoginRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	cookies := r.CookiesNamed(EmailLoginCookie)
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
	http.SetCookie(w, &http.Cookie{Name: EmailLoginCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}
