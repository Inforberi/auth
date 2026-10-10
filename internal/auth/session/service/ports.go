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
	RefreshSession(ctx context.Context, tokenHash string, session *sessiondomain.Session, expectedExpiry time.Time) (bool, error)
}

type clock interface {
	NowUTC() time.Time
}

type tokenManager interface {
	GenerateToken(lengths ...int) (string, error)
	Hash(rawToken string) string
}
