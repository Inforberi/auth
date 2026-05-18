package register_service

import "github.com/Inforberi/financial-intelligence/internal/core/domain"

type hasher interface {
	GenerateHash(password, salt []byte) (*domain.HashSalt, error)
	Compare(hash, salt, password []byte) error
}

// type repo interface{

// }

type RegisterService struct {
	hasher hasher
}

func New(hasher hasher) *RegisterService {

	return &RegisterService{hasher: hasher}
}
