package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	provisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
)

type OperatorRepository interface {
	AuthorizeRead(context.Context, domain.Principal, domain.Permission) error
	ListOperators(context.Context, domain.Principal, accountdomain.UserID) ([]domain.Operator, error)
	Manage(context.Context, domain.Principal, domain.Management, provisioning.ProvisionCommand, time.Duration) (accountdomain.UserID, error)
}

type Management struct {
	repo        OperatorRepository
	invitations *provisioning.ProvisionService
	freshFor    time.Duration
}

func NewManagement(repo OperatorRepository, invitations *provisioning.ProvisionService, freshFor time.Duration) *Management {
	return &Management{repo: repo, invitations: invitations, freshFor: freshFor}
}

func (s *Management) List(ctx context.Context, actor domain.Principal, after accountdomain.UserID) ([]domain.Operator, error) {
	if after != "" && !accountdomain.ValidUserID(after) {
		return nil, domain.ErrInvalidManagement
	}
	if err := s.repo.AuthorizeRead(ctx, actor, domain.OperatorsManage); err != nil {
		return nil, err
	}
	return s.repo.ListOperators(ctx, actor, after)
}

func (s *Management) Apply(ctx context.Context, actor domain.Principal, input domain.Management) (accountdomain.UserID, error) {
	input, err := input.Validate()
	if err != nil {
		return "", err
	}
	var invite provisioning.ProvisionCommand
	if input.Action == "invite" {
		if err := s.repo.AuthorizeRead(ctx, actor, domain.OperatorsManage); err != nil {
			return "", err
		}
		if s.invitations == nil {
			return "", accountdomain.ErrProvisionDisabled
		}
		invite, err = s.invitations.PreparePlatformInvitation(ctx, actor.UserID, input.Email)
		if err != nil {
			return "", err
		}
	}
	return s.repo.Manage(ctx, actor, input, invite, s.freshFor)
}
