package httpx

import (
	"fmt"
	"net/http"
	"time"
)

const SessionCookieName = "__Host-session"

func SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func GetSessionCookie(r *http.Request) (string, error) {
	token, err := r.Cookie(SessionCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", fmt.Errorf("cookie not found %w", err)
		}
		return "", fmt.Errorf("get session cookie %w", err)
	}

	return token.Value, nil
}
