package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *Service) Authorize(ctx context.Context, principal Principal, permission domain.PermissionKey) error {
	if !s.catalog.Contains(permission) || !accountdomain.ValidUserID(principal.UserID) || len(principal.TokenHash) != 64 {
		return domain.ErrForbidden
	}
	if _, err := hex.DecodeString(principal.TokenHash); err != nil {
		return domain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	allowed, err := s.repository.HasPermission(ctx, principal, permission)
	if err != nil {
		return fmt.Errorf("check access: %w", err)
	}
	if !allowed {
		return domain.ErrForbidden
	}
	return nil
}
