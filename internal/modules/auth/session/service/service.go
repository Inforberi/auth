package service

import (
	"context"
	"time"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

type sessionRepo interface {
	CreateSession(
		ctx context.Context,
		sessionParams sessionmodel.CreateSessionParams,
	) error
	FindSession(ctx context.Context, tokenHash string) (*sessionmodel.Session, error)
	UpdateSession(ctx context.Context, tokenHash string, session *sessionmodel.Session, ttl time.Duration) error
	DeleteSession(ctx context.Context, tokenHash string, userID accountmodel.UserID) error
	DeleteAllSessions(ctx context.Context, userID accountmodel.UserID) error
	DeleteAllSessionsExcept(ctx context.Context, userID accountmodel.UserID, tokenHash string) error
}

type clock interface {
	NowUTC() time.Time
}

type tokenManager interface {
	GenerateToken(lengths ...int) (string, error)
	Hash(rawToken string) string
}

type SessionService struct {
	now   clock
	repo  sessionRepo
	token tokenManager
	cfg   sessionmodel.Config
}

func New(now clock, repo sessionRepo, token tokenManager, cfg sessionmodel.Config) *SessionService {
	return &SessionService{
		now:   now,
		repo:  repo,
		token: token,
		cfg:   cfg,
	}
}
