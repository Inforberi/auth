package mfaloginhttp

import (
	"net/http"
	"time"

	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

const LoginCookie = "__Host-mfa-login"

type ChallengeResponse struct {
	Method    string    `json:"method,omitempty"`
	Status    string    `json:"status"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name mfa_http.ChallengeResponse

func RespondChallenge(w http.ResponseWriter, challenge *mfalogin.LoginChallenge) {
	RespondChallengeWithCookie(w, challenge, LoginCookie)
}

func RespondChallengeWithCookie(w http.ResponseWriter, challenge *mfalogin.LoginChallenge, cookieName string) {
	if cookieName == "" {
		cookieName = LoginCookie
	}
	sessionhttp.ClearSessionCookie(w)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: challenge.Binding, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: challenge.ExpiresAt})
	status := "mfa_required"
	if challenge.EnrollmentRequired {
		status = "mfa_enrollment_required"
	}
	if challenge.RecoveryRequired {
		status = "mfa_recovery_required"
	}
	httpx.JSON(w, 202, ChallengeResponse{Method: string(challenge.Method), Status: status, Challenge: challenge.Token, ExpiresAt: challenge.ExpiresAt})
}

func LoginBinding(r *http.Request) string {
	if cookies := r.CookiesNamed(LoginCookie); len(cookies) == 1 {
		return cookies[0].Value
	}
	return ""
}

func ClearLoginCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: LoginCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
