package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type statusRepository interface {
	ChangeStatus(context.Context, domain.StatusChange) (domain.AuthVersion, error)
}

type StatusService struct{ repo statusRepository }

func NewStatus(repo statusRepository) *StatusService { return &StatusService{repo: repo} }

func (s *StatusService) Change(ctx context.Context, change domain.StatusChange) (domain.AuthVersion, error) {
	if err := change.Validate(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.ChangeStatus(ctx, change)
}
