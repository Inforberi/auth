package service

import (
	"context"
	"time"
)

func (s *Service) AllowRegistration(ctx context.Context, ip string) error {
	if err := s.limit(ctx, "register-ip:"+ip, s.cfg.RegistrationIPLimit, time.Minute); err != nil {
		return err
	}
	return s.limit(ctx, "register-global", s.cfg.RegistrationGlobalLimit, time.Minute)
}
