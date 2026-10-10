package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
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
			m.respondError(w, r, err)
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

type SessionService interface {
	ValidateSession(ctx context.Context, rawToken string) (*sessionservice.ValidateSession, error)
}

type Middleware struct {
	session SessionService
	log     *zap.Logger
}

func New(session SessionService, log *zap.Logger) *Middleware {
	return &Middleware{
		session: session,
		log:     log,
	}
}
