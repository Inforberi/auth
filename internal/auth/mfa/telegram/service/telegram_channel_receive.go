package service

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type TelegramStart struct {
	BotID, TelegramID, UpdateID int64
	Binding                     string
}

type TelegramCandidate struct {
	Bot                  domain.TelegramBotBinding
	Digest, Verifier     string
	TelegramID, UpdateID int64
	Payload              []byte
}

type TelegramEnvelope struct {
	TelegramID int64
	Payload    []byte
	ExpiresAt  time.Time
}

type TelegramDelivery struct {
	TelegramID int64
	Code       string `json:"-"`
	ExpiresAt  time.Time
}

type telegramCode struct {
	TelegramID int64  `json:"telegramId"`
	Code       string `json:"code"`
}

// Receive accepts only a trusted adapter's authenticated private-start projection.
func (s *TelegramPreparation) Receive(ctx context.Context, input TelegramStart) (*TelegramDelivery, error) {
	if input.BotID != s.cfg.Bot.ID || !domain.ValidTelegramID(input.TelegramID) || input.UpdateID < 0 || !mfaservice.ValidToken(input.Binding) {
		return nil, domain.ErrInvalidTelegramPreparation
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := mfaservice.AdmitBudgets(ctx, s.limits, []mfaservice.Budget{
		{Key: s.cipher.Digest("telegram-channel:update:user:" + strconv.FormatInt(input.TelegramID, 10)), Count: 5},
		{Key: s.cipher.Digest("telegram-channel:update:binding:" + input.Binding), Count: 5},
		{Key: s.cipher.Digest("telegram-channel:update:project"), Count: s.cfg.UpdatesPerMinute},
	}); err != nil {
		return nil, err
	}
	code, err := s.tokens.GenerateCode()
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	plain, err := json.Marshal(telegramCode{TelegramID: input.TelegramID, Code: code})
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	defer clear(plain)
	payload, err := s.cipher.Seal(plain)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	stored, err := s.repo.ReceiveTelegramPreparation(ctx, TelegramCandidate{
		Bot:        s.cfg.Bot,
		Digest:     s.digest(input.Binding),
		Verifier:   s.verifier(input.Binding, code),
		TelegramID: input.TelegramID,
		UpdateID:   input.UpdateID,
		Payload:    payload,
	})
	if err != nil {
		return nil, err
	}
	decrypted, err := s.cipher.Open(stored.Payload)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	defer clear(decrypted)
	var message telegramCode
	if json.Unmarshal(decrypted, &message) != nil || message.TelegramID != input.TelegramID || stored.TelegramID != input.TelegramID || !domain.ValidTelegramCode(message.Code) {
		return nil, domain.ErrUnavailable
	}
	return &TelegramDelivery{TelegramID: message.TelegramID, Code: message.Code, ExpiresAt: stored.ExpiresAt}, nil
}
