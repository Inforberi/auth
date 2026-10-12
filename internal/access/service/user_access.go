package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

func (s *Service) UserAccess(ctx context.Context, principal Principal) (domain.UserAccess, error) {
	if !validPrincipal(principal) {
		return domain.UserAccess{}, domain.ErrForbidden
	}
	permissions := s.catalog.Permissions()
	keys := make([]domain.PermissionKey, 0, len(permissions))
	for _, permission := range permissions {
		keys = append(keys, permission.Key)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repository.ReadAccess(ctx, principal, keys)
}
