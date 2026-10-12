package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type AssignmentInput struct {
	Actor                 Principal
	UserID                accountdomain.UserID
	RoleID                domain.RoleID
	ExpectedRoleVersion   int64
	ExpectedAccessVersion int64
	Grant                 bool
}

func (s *Service) ChangeAssignment(ctx context.Context, input AssignmentInput) (int64, error) {
	if !validPrincipal(input.Actor) || (input.Grant && input.Actor.UserID == input.UserID) {
		return 0, domain.ErrForbidden
	}
	if !accountdomain.ValidUserID(input.UserID) || !accountdomain.ValidUserID(accountdomain.UserID(input.RoleID)) ||
		input.ExpectedRoleVersion < 1 || input.ExpectedAccessVersion < 1 {
		return 0, domain.ErrInvalidRole
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repository.ChangeAssignment(ctx, input)
}
