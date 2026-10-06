package http

import (
	"context"

	"go.uber.org/zap"

	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

type SessionService interface {
	ValidateSession(ctx context.Context, rawToken string) (*sessionmodel.ValidateSession, error)
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
