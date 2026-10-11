package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

// ReadRole and ListRoles are trusted-caller queries, not administrative authorization.
func (s *Service) ReadRole(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	if !accountdomain.ValidUserID(accountdomain.UserID(id)) {
		return domain.Role{}, domain.ErrInvalidRole
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repository.ReadRole(ctx, id)
}

func (s *Service) ListRoles(ctx context.Context, afterKey string, limit int) ([]domain.Role, error) {
	if (afterKey != "" && !domain.ValidKey(afterKey)) || limit < 1 || limit > 100 {
		return nil, domain.ErrInvalidRole
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repository.ListRoles(ctx, afterKey, limit)
}
