package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
)

type RequestedCode struct {
	Binding   string
	ExpiresAt time.Time
}

func (s *Service) Request(ctx context.Context, input, ip string) (*RequestedCode, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrDisabled
	}
	email, err := accountdomain.NewEmail(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.requestLimits(ctx, email.String(), ip); err != nil {
		return nil, err
	}
	result, challenge, err := s.prepareCode(email.String(), "входа", "")
	if err != nil {
		return nil, err
	}
	if err := s.repo.Issue(ctx, email.String(), challenge); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) requestLimits(ctx context.Context, email, ip string) error {
	for _, budget := range []struct {
		key    string
		count  int
		window time.Duration
	}{
		{"request:ip:" + ip, 10, time.Minute},
		{"request:project", s.cfg.RequestGlobalLimit, time.Minute},
		{"request:email:" + email, 3, 15 * time.Minute},
		{"request:cooldown:" + email, 1, s.cfg.ResendInterval},
	} {
		if err := s.limit(ctx, budget.key, budget.count, budget.window); err != nil {
			return err
		}
	}
	return nil
}
