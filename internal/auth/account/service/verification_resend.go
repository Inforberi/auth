package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *Service) Resend(ctx context.Context, input, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	email, err := domain.NewEmail(input)
	if err != nil {
		return err
	}
	if err := s.limit(ctx, "resend-ip:"+ip, 10, time.Minute); err != nil {
		return err
	}
	if err := s.limit(ctx, "resend-email:"+email.String(), 3, 15*time.Minute); err != nil {
		return err
	}
	prepared, err := s.PrepareVerification(email.String())
	if err != nil {
		return err
	}
	return s.repo.Issue(ctx, email.String(), prepared, s.cfg.ResendInterval)
}
