package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type deletionRepository interface {
	DeleteAccount(context.Context, domain.AccountDeletion) (domain.AuthVersion, error)
}

type DeletionService struct{ repo deletionRepository }

func NewDeletion(repo deletionRepository) *DeletionService { return &DeletionService{repo: repo} }

func (s *DeletionService) Delete(ctx context.Context, deletion domain.AccountDeletion) (domain.AuthVersion, error) {
	if err := deletion.Validate(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.DeleteAccount(ctx, deletion)
}
