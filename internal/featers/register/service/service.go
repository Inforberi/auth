package register_service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

type hasher interface {
	GenerateHash(password, salt []byte) (*domain.HashSalt, error)
	Compare(hash, salt, password []byte) error
}

type registerRepo interface {
	ExistsByEmail(ctx context.Context, email string) (bool, error)
}

type RegisterService struct {
	hasher hasher
	repo   registerRepo
}

func New(hasher hasher, repo registerRepo) *RegisterService {
	return &RegisterService{hasher: hasher, repo: repo}
}
