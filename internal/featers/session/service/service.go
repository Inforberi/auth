package session_service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/clock"
)

type repo interface {
	CreateSession(ctx context.Context, userID domain.UserID, expiredTime time.Time, tokenHash, userAgent, IP string) (domain.SessionID, error)
}

type tokenManager interface {
	GenerateSessionToken() (string, error)
	Hash(rawToken string) string
}

type SessionService struct {
	now   clock.UTCClock
	repo  repo
	token tokenManager
	cfg   config.SessionConfig
}

func New(now clock.UTCClock, repo repo, token tokenManager, cfg config.SessionConfig) *SessionService {
	return &SessionService{
		now:   now,
		repo:  repo,
		token: token,
		cfg:   cfg,
	}
}
