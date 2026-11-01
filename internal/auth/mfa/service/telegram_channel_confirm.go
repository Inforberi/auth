package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type ConfirmTelegramChannel struct {
	Proof         Proof
	Binding, Code string
	IP            string
}

type TelegramConfirmation struct {
	Bot                           domain.TelegramBotBinding
	Digest, Verifier, SessionHash string
}

type TelegramPrepared struct {
	BotID, TelegramID int64
	Token             string `json:"-"`
	ExpiresAt         time.Time
}

func (s *TelegramPreparation) Confirm(ctx context.Context, input ConfirmTelegramChannel) (*TelegramPrepared, error) {
	if err := input.Proof.Validate(); err != nil {
		return nil, err
	}
	if !validLoginToken(input.Binding) || !domain.ValidTelegramCode(input.Code) {
		return nil, domain.ErrInvalidTelegramPreparation
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admitBrowser(ctx, input.Proof, input.IP, "confirm", s.cfg.ConfirmationsPerMinute); err != nil {
		return nil, err
	}
	raw, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	result, err := s.repo.ConfirmTelegramPreparation(ctx, input.Proof, TelegramConfirmation{
		Bot: s.cfg.Bot, Digest: s.digest(input.Binding), Verifier: s.verifier(input.Binding, input.Code), SessionHash: s.tokens.Hash(raw),
	})
	if err != nil {
		return nil, err
	}
	result.Token = raw
	return result, nil
}
