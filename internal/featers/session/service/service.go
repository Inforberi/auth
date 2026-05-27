package session_service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/clock"
	session_redis "github.com/Inforberi/financial-intelligence/internal/featers/session/repo/redis"
)

type sessionRepo interface {
	Create(
		ctx context.Context,
		sessionParams session_redis.CreateSessionParams,
	) error
}

type tokenManager interface {
	GenerateSessionToken() (string, error)
	Hash(rawToken string) string
}

type SessionService struct {
	now   clock.UTCClock
	repo  sessionRepo
	token tokenManager
	cfg   config.SessionConfig
}

func New(now clock.UTCClock, repo sessionRepo, token tokenManager, cfg config.SessionConfig) *SessionService {
	return &SessionService{
		now:   now,
		repo:  repo,
		token: token,
		cfg:   cfg,
	}
}
