package httpx

import (
	"net/http"
	"time"
)

func SetSessionCookie(w http.ResponseWriter, token string, expiredAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiredAt,
	})
}
