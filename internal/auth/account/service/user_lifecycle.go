package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type userLifecycleRepository interface {
	ChangeUserStatus(context.Context, accessservice.Principal, domain.StatusChange) (domain.AuthVersion, error)
	DeleteUserAccount(context.Context, accessservice.Principal, domain.AccountDeletion) (domain.AuthVersion, error)
}

type UserLifecycle struct{ repo userLifecycleRepository }

func NewUserLifecycle(repo userLifecycleRepository) *UserLifecycle { return &UserLifecycle{repo: repo} }

func (s *UserLifecycle) ChangeStatus(ctx context.Context, actor accessservice.Principal, change domain.StatusChange) (domain.AuthVersion, error) {
	if actor.Validate() != nil {
		return 0, accessdomain.ErrForbidden
	}
	change.ActorID = actor.UserID
	if err := change.Validate(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.ChangeUserStatus(ctx, actor, change)
}

func (s *UserLifecycle) Delete(ctx context.Context, actor accessservice.Principal, deletion domain.AccountDeletion) (domain.AuthVersion, error) {
	if actor.Validate() != nil {
		return 0, accessdomain.ErrForbidden
	}
	deletion.ActorID = actor.UserID
	if err := deletion.Validate(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.DeleteUserAccount(ctx, actor, deletion)
}
