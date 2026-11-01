package service

import (
	"context"
	"net/netip"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type TelegramPreparationConfig struct {
	Bot                    domain.TelegramBotBinding
	TTL                    time.Duration
	RequestsPerMinute      int
	UpdatesPerMinute       int
	ConfirmationsPerMinute int
}

func (c TelegramPreparationConfig) Validate() error {
	if !c.Bot.Valid() || c.TTL < time.Minute || c.TTL > 5*time.Minute ||
		c.RequestsPerMinute < 1 || c.UpdatesPerMinute < 1 || c.ConfirmationsPerMinute < 1 {
		return domain.ErrUnavailable
	}
	return nil
}

type telegramPreparationRepository interface {
	IssueTelegramPreparation(context.Context, Proof, TelegramIntent) (time.Time, error)
	ReceiveTelegramPreparation(context.Context, TelegramCandidate) (*TelegramEnvelope, error)
	ConfirmTelegramPreparation(context.Context, Proof, TelegramConfirmation) (*TelegramPrepared, error)
}

type telegramPreparationTokens interface {
	loginTokens
	GenerateCode() (string, error)
}

type TelegramPreparation struct {
	repo   telegramPreparationRepository
	cipher Cipher
	limits Limiter
	tokens telegramPreparationTokens
	cfg    TelegramPreparationConfig
}

func NewTelegramPreparation(repo telegramPreparationRepository, cipher Cipher, limits Limiter, tokens telegramPreparationTokens, cfg TelegramPreparationConfig) (*TelegramPreparation, error) {
	if repo == nil || cipher == nil || limits == nil || tokens == nil || cfg.Validate() != nil {
		return nil, domain.ErrUnavailable
	}
	return &TelegramPreparation{repo: repo, cipher: cipher, limits: limits, tokens: tokens, cfg: cfg}, nil
}

func (s *TelegramPreparation) admitBrowser(ctx context.Context, proof Proof, ip, phase string, count int) error {
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" {
		return domain.ErrInvalidTelegramPreparation
	}
	return admitBudgets(ctx, s.limits, []Budget{
		{s.cipher.Digest("telegram-channel:" + phase + ":user:" + string(proof.UserID)), 5},
		{s.cipher.Digest("telegram-channel:" + phase + ":ip:" + address.Unmap().String()), 10},
		{s.cipher.Digest("telegram-channel:" + phase + ":project"), count},
	})
}

func (s *TelegramPreparation) digest(binding string) string {
	return s.cipher.Digest("telegram-channel:binding:" + binding)
}

func (s *TelegramPreparation) verifier(binding, code string) string {
	return s.cipher.Digest("telegram-channel:code:" + binding + ":" + code)
}
