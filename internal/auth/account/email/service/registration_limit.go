package service

import (
	"context"
	"time"
)

func (s *Verification) AllowRegistration(ctx context.Context, ip string) error {
	ipLimit, globalLimit := s.cfg.RegistrationIPLimit, s.cfg.RegistrationGlobalLimit
	if s.cfg.RegistrationBudgetSource != nil {
		var err error
		ipLimit, globalLimit, err = s.cfg.RegistrationBudgetSource(ctx)
		if err != nil {
			return err
		}
	}
	if err := s.limit(ctx, "register-ip:"+ip, ipLimit, time.Minute); err != nil {
		return err
	}
	return s.limit(ctx, "register-global", globalLimit, time.Minute)
}
