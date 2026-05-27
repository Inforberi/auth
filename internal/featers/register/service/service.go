package register_service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
)

type hasher interface {
	GenerateHash(password []byte) (string, error)
	Compare(password string, encodedHash string) error
}

type registerRepo interface {
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, email, passwordHash string) (domain.UserID, error)
}

type session interface {
	CreateSession(ctx context.Context, userID domain.UserID, userAgent, IP string) (*session_service.Session, error)
}

type registerService struct {
	hasher  hasher
	repo    registerRepo
	session session
}

func New(hasher hasher, repo registerRepo, session session) *registerService {
	return &registerService{hasher: hasher, repo: repo, session: session}
}
