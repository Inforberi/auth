package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *Verification) Resend(ctx context.Context, input, ip string) error {
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
	ttl := s.cfg.TTL
	if s.cfg.TTLSource != nil {
		ttl, err = s.cfg.TTLSource(ctx)
		if err != nil {
			return err
		}
	}
	address := s.cfg.URL
	if s.cfg.URLSource != nil {
		address, err = s.cfg.URLSource(ctx)
		if err != nil {
			return err
		}
	}
	prepared, err := s.PrepareVerificationLink(email.String(), address, ttl)
	if err != nil {
		return err
	}
	return s.repo.Issue(ctx, email.String(), prepared, s.cfg.ResendInterval)
}
