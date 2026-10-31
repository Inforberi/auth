package mfahttp

import (
	"net/http"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

const EmailLoginCookie = "__Host-mfa-email"

type EmailLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
} // @name mfa_http.EmailLoginRequest

// StartEmailLogin validates the password and returns only a browser-bound email challenge.
func (h *EmailHandler) StartEmailLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input EmailLoginRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	proof, err := h.password.Authenticate(r.Context(), passwordservice.LoginInput{Email: input.Email, Password: input.Password, UserAgent: httpx.UserAgent(r), IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	challenge, err := h.login.Start(r.Context(), proof, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	http.SetCookie(w, &http.Cookie{Name: EmailLoginCookie, Value: challenge.Binding, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: challenge.ExpiresAt})
	httpx.JSON(w, 202, ChallengeResponse{Status: "email_mfa_required", Challenge: challenge.Token, ExpiresAt: challenge.ExpiresAt})
}
