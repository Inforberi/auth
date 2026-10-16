package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

// CheckPublic is early admission before hashing/provider work. SQL rechecks at commit.
func (s *Service) CheckPublic(ctx context.Context, method string, registration bool) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	snapshot, err := s.repo.Load(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrPolicyUnavailable, err)
	}
	return snapshot.Policy.RequireMethod(method, registration)
}
