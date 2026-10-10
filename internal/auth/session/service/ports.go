package service

import (
	"context"
	"time"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

type sessionRepo interface {
	CreateSession(
		ctx context.Context,
		sessionParams CreateSessionParams,
	) error
	FindSession(ctx context.Context, tokenHash string) (*sessiondomain.Session, error)
	UpdateSession(ctx context.Context, tokenHash string, session *sessiondomain.Session, ttl time.Duration) error
}

type clock interface {
	NowUTC() time.Time
}

type tokenManager interface {
	GenerateToken(lengths ...int) (string, error)
	Hash(rawToken string) string
}
