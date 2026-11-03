package service

import (
	"context"
	"net/netip"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type TelegramPreparationConfig struct {
	UserLimitPerMinute, IPLimitPerMinute int
	Bot                                  domain.TelegramBotBinding
	TTL                                  time.Duration
	RequestsPerMinute                    int
	UpdatesPerMinute                     int
	ConfirmationsPerMinute               int
}

func (c TelegramPreparationConfig) Validate() error {
	if c.UserLimitPerMinute < 0 || c.IPLimitPerMinute < 0 || !c.Bot.Valid() || c.TTL < time.Minute || c.TTL > 5*time.Minute ||
		c.RequestsPerMinute < 1 || c.UpdatesPerMinute < 1 || c.ConfirmationsPerMinute < 1 {
		return domain.ErrUnavailable
	}
	return nil
}

type telegramPreparationRepository interface {
	IssueTelegramPreparation(context.Context, mfaservice.Proof, TelegramIntent) (time.Time, error)
	ReceiveTelegramPreparation(context.Context, TelegramCandidate) (*TelegramEnvelope, error)
	ConfirmTelegramPreparation(context.Context, mfaservice.Proof, TelegramConfirmation) (*TelegramPrepared, error)
}

type telegramPreparationTokens interface {
	mfaservice.Tokens
	GenerateCode() (string, error)
}

type TelegramPreparation struct {
	repo   telegramPreparationRepository
	cipher mfaservice.Cipher
	limits mfaservice.Limiter
	tokens telegramPreparationTokens
	cfg    TelegramPreparationConfig
}

func NewTelegramPreparation(repo telegramPreparationRepository, cipher mfaservice.Cipher, limits mfaservice.Limiter, tokens telegramPreparationTokens, cfg TelegramPreparationConfig) (*TelegramPreparation, error) {
	if repo == nil || cipher == nil || limits == nil || tokens == nil || cfg.Validate() != nil {
		return nil, domain.ErrUnavailable
	}
	if cfg.UserLimitPerMinute == 0 {
		cfg.UserLimitPerMinute = 5
	}
	if cfg.IPLimitPerMinute == 0 {
		cfg.IPLimitPerMinute = 10
	}
	return &TelegramPreparation{repo: repo, cipher: cipher, limits: limits, tokens: tokens, cfg: cfg}, nil
}

func (s *TelegramPreparation) admitBrowser(ctx context.Context, proof mfaservice.Proof, ip, phase string, count int) error {
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" {
		return domain.ErrInvalidTelegramPreparation
	}
	return mfaservice.AdmitBudgets(ctx, s.limits, []mfaservice.Budget{
		{Key: s.cipher.Digest("telegram-channel:" + phase + ":user:" + string(proof.UserID)), Count: s.cfg.UserLimitPerMinute},
		{Key: s.cipher.Digest("telegram-channel:" + phase + ":ip:" + address.Unmap().String()), Count: s.cfg.IPLimitPerMinute},
		{Key: s.cipher.Digest("telegram-channel:" + phase + ":project"), Count: count},
	})
}

func (s *TelegramPreparation) digest(binding string) string {
	return s.cipher.Digest("telegram-channel:binding:" + binding)
}

func (s *TelegramPreparation) verifier(binding, code string) string {
	return s.cipher.Digest("telegram-channel:code:" + binding + ":" + code)
}
