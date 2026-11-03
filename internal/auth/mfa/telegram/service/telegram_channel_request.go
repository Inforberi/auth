package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type TelegramIntent struct {
	Bot    domain.TelegramBotBinding
	Digest string
	TTL    time.Duration
}

type TelegramStarted struct {
	URL       string
	Binding   string
	ExpiresAt time.Time
}

func (s *TelegramPreparation) Request(ctx context.Context, proof mfaservice.Proof, ip string) (*TelegramStarted, error) {
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admitBrowser(ctx, proof, ip, "request", s.cfg.RequestsPerMinute); err != nil {
		return nil, err
	}
	binding, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	expires, err := s.repo.IssueTelegramPreparation(ctx, proof, TelegramIntent{Bot: s.cfg.Bot, Digest: s.digest(binding), TTL: s.cfg.TTL})
	if err != nil {
		return nil, err
	}
	return &TelegramStarted{Binding: binding, ExpiresAt: expires}, nil
}
