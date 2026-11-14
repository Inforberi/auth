package service

import (
	"context"
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type TemporaryLoginResult struct {
	Token     string
	ExpiresAt time.Time
}

func (s *TemporaryPasswordService) Login(ctx context.Context, rawEmail, password, ip string) (*TemporaryLoginResult, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrTemporaryPasswordDisabled
	}
	email, err := passwordservice.ParseCredentials(rawEmail, password)
	if err != nil {
		return nil, err
	}
	if len(password) > 1024 {
		return nil, domain.ErrInvalidTemporaryPassword
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if s.loginLimit == nil {
		return nil, domain.ErrLoginUnavailable
	}
	if err := s.loginLimit.Allow(ctx, email.String(), ip); err != nil {
		return nil, err
	}
	credential, err := s.repo.FindTemporary(ctx, email.String())
	if err != nil {
		return nil, err
	}
	if err := s.hash.Compare(ctx, password, credential.PasswordHash); err != nil {
		if errors.Is(err, domain.ErrHashBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, domain.ErrInvalidTemporaryPassword
	}
	token, err := temporarySecret()
	if err != nil {
		return nil, err
	}
	ttl := s.cfg.SetupTTL
	if s.cfg.SetupTTLSource != nil {
		ttl, err = s.cfg.SetupTTLSource(ctx)
		if err != nil {
			return nil, err
		}
	}
	expires, err := s.repo.BeginTemporary(ctx, *credential, passwordservice.TokenDigest(token), ttl)
	if err != nil {
		return nil, err
	}
	return &TemporaryLoginResult{Token: token, ExpiresAt: expires}, nil
}
