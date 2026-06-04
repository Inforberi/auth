package password_service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
)

type session interface {
	CreateSession(ctx context.Context, userID domain.UserID, userAgent, IP string) (*session_service.Session, error)
	LogoutAllExcept(ctx context.Context, tokenHash string, userID domain.UserID) error
}

type passwordRepo interface {
	FindByEmail(ctx context.Context, email string) (*password_domain.FindByEmailResult, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, email, passwordHash string) (domain.UserID, error)
}

type hasher interface {
	GenerateHash(password []byte) (string, error)
	Compare(password string, encodedHash string) error
}

type clock interface {
	NowUTC() time.Time
}

type PasswordService struct {
	repo    passwordRepo
	session session
	hash    hasher
	now     clock
}

func New(repo passwordRepo, session session, hash hasher, now clock) *PasswordService {
	return &PasswordService{
		repo:    repo,
		session: session,
		hash:    hash,
		now:     now,
	}
}
