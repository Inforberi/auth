package session_service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
)

type sessionRepo interface {
	CreateSession(
		ctx context.Context,
		sessionParams session_domain.CreateSessionParams,
	) error
	FindSession(ctx context.Context, tokenHash string) (*session_domain.Session, error)
	UpdateSession(ctx context.Context, tokenHash string, session *session_domain.Session, ttl time.Duration) error
	DeleteSession(ctx context.Context, tokenHash string, userID domain.UserID) error
	DeleteAllSessions(ctx context.Context, userID domain.UserID) error
	DeleteAllSessionsExcept(ctx context.Context, userID domain.UserID, tokenHash string) error
}

type clock interface {
	NowUTC() time.Time
}

type tokenManager interface {
	GenerateToken(lengths ...int) (string, error)
	Hash(rawToken string) string
}

type Session struct {
	RawToken  string
	ExpiresAt time.Time
}

type SessionService struct {
	now   clock
	repo  sessionRepo
	token tokenManager
	cfg   config.SessionConfig
}

func New(now clock, repo sessionRepo, token tokenManager, cfg config.SessionConfig) *SessionService {
	return &SessionService{
		now:   now,
		repo:  repo,
		token: token,
		cfg:   cfg,
	}
}
