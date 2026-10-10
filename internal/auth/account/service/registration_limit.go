package service

import (
	"context"
	"time"
)

func (s *Service) AllowRegistration(ctx context.Context, ip string) error {
	if err := s.limit(ctx, "register-ip:"+ip, 5, time.Minute); err != nil {
		return err
	}
	return s.limit(ctx, "register-global", 100, time.Minute)
}
