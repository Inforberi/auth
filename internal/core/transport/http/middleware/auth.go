package core_middleware

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
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
		token, err := httpx.GetSessionCookie(r)
		if err != nil {
			unauthorized(w)
			return
		}

		session, err := m.session.ValidateSession(r.Context(), token)
		if err != nil {
			unauthorized(w)
			return
		}

		ctx := httpx.SetAuthContext(
			r.Context(),
			httpx.Auth{
				UserID:    session.UserID,
				TokenHash: session.TokenHash,
			})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
