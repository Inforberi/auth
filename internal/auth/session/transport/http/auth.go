package http

import (
	"errors"
	"net/http"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func unauthorized(w http.ResponseWriter) {
	httpx.Error(
		w,
		http.StatusUnauthorized,
		"unauthorized",
		"unauthorized",
	)
}

func (m *Middleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := GetSessionCookie(r)
		if err != nil {
			unauthorized(w)
			return
		}

		session, err := m.session.ValidateSession(r.Context(), token)
		if err != nil {
			if errors.Is(err, sessiondomain.ErrSessionNotFound) || errors.Is(err, sessiondomain.ErrSessionExpired) {
				unauthorized(w)
			} else {
				httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
			}
			return
		}

		ctx := SetAuthContext(
			r.Context(),
			Auth{
				UserID:    session.UserID,
				TokenHash: session.TokenHash,
			})

		if session.Extended {
			SetSessionCookie(w, token, session.ExpiresAt)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
