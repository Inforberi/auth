package service

import (
	"context"
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type TemporaryLoginResult struct {
	Token     string
	ExpiresAt time.Time
}

func (s *TemporaryPasswordService) Login(ctx context.Context, rawEmail, password, ip string) (*TemporaryLoginResult, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrTemporaryPasswordDisabled
	}
	email, err := parseCredentials(rawEmail, password)
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
	expires, err := s.repo.BeginTemporary(ctx, *credential, resetDigest(token), s.cfg.SetupTTL)
	if err != nil {
		return nil, err
	}
	return &TemporaryLoginResult{Token: token, ExpiresAt: expires}, nil
}
