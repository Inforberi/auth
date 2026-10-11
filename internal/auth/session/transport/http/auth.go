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
	return m.authenticate(next, false, true)
}

func (m *Middleware) LogoutAuth(next http.Handler) http.Handler {
	return m.authenticate(next, true, false)
}

func (m *Middleware) NoRefreshAuth(next http.Handler) http.Handler {
	return m.authenticate(next, false, false)
}

func (m *Middleware) authenticate(next http.Handler, clearInvalid, refreshCookie bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := GetSessionCookie(r)
		if err != nil {
			if clearInvalid {
				ClearSessionCookie(w)
			}
			unauthorized(w)
			return
		}

		validate := m.session.ValidateSession
		if !refreshCookie {
			validate = m.session.ValidateSessionWithoutRefresh
		}
		session, err := validate(r.Context(), token)
		if err != nil {
			if clearInvalid && httpx.MapError(err, sessionErrors, httpx.Failure{Status: 503}).Status == 401 {
				ClearSessionCookie(w)
			}
			m.respondError(w, r, err)
			return
		}

		ctx := SetAuthContext(
			r.Context(),
			Auth{
				SessionID: session.SessionID,
				UserID:    session.UserID,
				TokenHash: session.TokenHash,
			})

		if session.Extended && refreshCookie {
			SetSessionCookie(w, token, session.ExpiresAt)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type SessionService interface {
	ValidateSession(ctx context.Context, rawToken string) (*sessionservice.ValidationResult, error)
	ValidateSessionWithoutRefresh(ctx context.Context, rawToken string) (*sessionservice.ValidationResult, error)
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
