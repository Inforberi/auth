package core_middleware

import (
	"context"

	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
	"go.uber.org/zap"
)

type SessionService interface {
	ValidateSession(ctx context.Context, rawToken string) (*session_domain.ValidateSession, error)
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
