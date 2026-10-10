package http

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const SessionCookieName = "__Host-session"

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}

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
		if errors.Is(err, http.ErrNoCookie) {
			return "", fmt.Errorf("cookie not found %w", err)
		}
		return "", fmt.Errorf("get session cookie %w", err)
	}

	if len(token.Value) != 43 {
		return "", errors.New("invalid session cookie")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token.Value)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token.Value {
		return "", errors.New("invalid session cookie")
	}
	return token.Value, nil
}
