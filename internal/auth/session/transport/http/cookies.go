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
	var token *http.Cookie
	for _, header := range r.Header.Values("Cookie") {
		// Request.Cookie silently skips malformed pairs and selects one duplicate.
		cookies, err := http.ParseCookie(header)
		if err != nil {
			return "", errors.New("invalid session cookie header")
		}
		for _, cookie := range cookies {
			if cookie.Name != SessionCookieName {
				continue
			}
			if token != nil {
				return "", errors.New("ambiguous session cookie")
			}
			token = cookie
		}
	}
	if token == nil {
		return "", fmt.Errorf("cookie not found: %w", http.ErrNoCookie)
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
