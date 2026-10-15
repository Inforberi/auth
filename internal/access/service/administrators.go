package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type AdministratorInput struct {
	Actor                 Principal
	UserID                accountdomain.UserID
	ExpectedAuthVersion   accountdomain.AuthVersion
	ExpectedAccessVersion int64
	ExpectedRoleVersion   int64
	Grant                 bool
}

func (s *Service) ChangeAdministrator(ctx context.Context, input AdministratorInput) (int64, error) {
	if !validPrincipal(input.Actor) || input.Grant && input.Actor.UserID == input.UserID {
		return 0, domain.ErrForbidden
	}
	if !accountdomain.ValidUserID(input.UserID) || input.ExpectedAuthVersion < 1 || input.ExpectedAccessVersion < 1 || input.ExpectedRoleVersion < 1 {
		return 0, domain.ErrInvalidRole
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repository.ChangeAdministrator(ctx, input)
}
