package login_service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/clock"
	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
)

type session interface {
	CreateSession(ctx context.Context, userID domain.UserID, userAgent, IP string) (*session_service.Session, error)
}

type loginRepo interface {
	FindByEmail(ctx context.Context, email string) (*login_domain.FindByEmailResult, error)
}

type hasher interface {
	Compare(password string, encodedHash string) error
}

type LoginService struct {
	repo    loginRepo
	session session
	hash    hasher
	now     clock.UTCClock
}

func New(repo loginRepo, session session, hash hasher, now clock.UTCClock) *LoginService {
	return &LoginService{
		repo:    repo,
		session: session,
		hash:    hash,
		now:     now,
	}
}
