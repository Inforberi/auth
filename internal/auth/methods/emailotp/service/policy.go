package service

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidPolicy = errors.New("invalid email OTP policy")

type Policy struct {
	TTLSeconds             int64 `json:"ttlSeconds"`
	ResendSeconds          int64 `json:"resendSeconds"`
	RequestsPerMinute      int   `json:"requestsPerMinute"`
	ConfirmationsPerMinute int   `json:"confirmationsPerMinute"`
}

func (c Config) Policy() Policy {
	return Policy{
		TTLSeconds: int64(c.TTL / time.Second), ResendSeconds: int64(c.ResendInterval / time.Second),
		RequestsPerMinute: c.RequestGlobalLimit, ConfirmationsPerMinute: c.ConfirmGlobalLimit,
	}
}

func (p Policy) Validate(ceiling Policy) error {
	if p.TTLSeconds < 60 || p.TTLSeconds > 600 || p.ResendSeconds < 60 || p.ResendSeconds >= p.TTLSeconds ||
		p.RequestsPerMinute < 1 || p.RequestsPerMinute > ceiling.RequestsPerMinute ||
		p.ConfirmationsPerMinute < 1 || p.ConfirmationsPerMinute > ceiling.ConfirmationsPerMinute {
		return ErrInvalidPolicy
	}
	return nil
}

func (s *Service) currentPolicy(ctx context.Context) (Policy, error) {
	if s.cfg.PolicySource == nil {
		return s.cfg.Policy(), nil
	}
	return s.cfg.PolicySource(ctx)
}
