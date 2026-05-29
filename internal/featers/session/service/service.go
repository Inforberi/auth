package session_service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
	session_redis "github.com/Inforberi/financial-intelligence/internal/featers/session/repo/redis"
)

type sessionRepo interface {
	CreateSession(
		ctx context.Context,
		sessionParams session_redis.CreateSessionParams,
	) error
	FindSession(ctx context.Context, tokenHash string) (*session_domain.Session, error)
	UpdateSession(ctx context.Context, tokenHash string, session *session_domain.Session, ttl time.Duration) error
}

type сlock interface {
	NowUTC() time.Time
}

type tokenManager interface {
	GenerateSessionToken() (string, error)
	Hash(rawToken string) string
}

type Session struct {
	RawToken  string
	ExpiresAt time.Time
}

type SessionService struct {
	now   сlock
	repo  sessionRepo
	token tokenManager
	cfg   config.SessionConfig
}

func New(now сlock, repo sessionRepo, token tokenManager, cfg config.SessionConfig) *SessionService {
	return &SessionService{
		now:   now,
		repo:  repo,
		token: token,
		cfg:   cfg,
	}
}
