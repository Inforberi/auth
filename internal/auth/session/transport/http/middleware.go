package http

import (
	"context"

	"go.uber.org/zap"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

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
