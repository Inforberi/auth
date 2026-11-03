package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type (
	SetupCompleteInput struct{ OperatorSecret, Token, EmailCode, TOTP, IP string }
	SetupCompleted     struct {
		RecoveryCodes []string `json:"-"`
	}
)

func (s *SetupService) Complete(ctx context.Context, input SetupCompleteInput) (*SetupCompleted, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, input.OperatorSecret, input.IP, "complete"); err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(input.Token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != input.Token || !domain.ValidEmailBindingCode(input.EmailCode) || (input.TOTP != "" && !mfadomain.ValidCode(input.TOTP)) {
		return nil, domain.ErrSetupInvalid
	}
	codes := []string{}
	err = s.repo.CompleteSetup(ctx, accountservice.TokenDigest(input.OperatorSecret), s.cipher.Digest("request:"+input.Token), func(encrypted []byte, now time.Time) (*domain.SetupAccount, error) {
		account, recovery, err := s.confirmSetup(input, encrypted, now)
		codes = recovery
		return account, err
	})
	if err != nil {
		return nil, err
	}
	return &SetupCompleted{RecoveryCodes: codes}, nil
}

func (s *SetupService) confirmSetup(input SetupCompleteInput, encrypted []byte, now time.Time) (*domain.SetupAccount, []string, error) {
	plain, err := s.cipher.Open(encrypted)
	if err != nil {
		return nil, nil, domain.ErrDependencyUnavailable
	}
	defer clear(plain)
	var pending setupPayload
	if err := json.Unmarshal(plain, &pending); err != nil {
		return nil, nil, domain.ErrDependencyUnavailable
	}
	if subtle.ConstantTimeCompare([]byte(pending.EmailDigest), []byte(s.cipher.Digest("email:"+input.Token+":"+input.EmailCode))) != 1 {
		return nil, nil, domain.ErrSetupInvalid
	}
	// Intents created before mode selection retain their required enrollment.
	if pending.MFAMode == "" {
		pending.MFAMode = settingsdomain.MFAAdministrators
	}
	if (settingsdomain.MFAPolicy{Mode: pending.MFAMode}).Validate() != nil {
		return nil, nil, domain.ErrDependencyUnavailable
	}
	account := &domain.SetupAccount{UserID: pending.UserID, Email: pending.Email, PasswordHash: pending.PasswordHash, MFAMode: pending.MFAMode}
	if pending.MFAMode == settingsdomain.MFAOptional {
		if pending.Secret != "" || input.TOTP != "" {
			return nil, nil, domain.ErrSetupInvalid
		}
		return account, []string{}, nil
	}
	if !mfadomain.ValidCode(input.TOTP) {
		return nil, nil, domain.ErrSetupInvalid
	}
	step, err := s.code.Match(pending.Secret, input.TOTP, now, -1)
	if errors.Is(err, mfadomain.ErrInvalidCode) {
		return nil, nil, domain.ErrSetupInvalid
	}
	if err != nil {
		return nil, nil, domain.ErrDependencyUnavailable
	}
	factor, err := s.factorCipher.Seal([]byte(string(pending.UserID) + "\x00" + pending.Secret))
	if err != nil {
		return nil, nil, domain.ErrDependencyUnavailable
	}
	codes := make([]string, mfadomain.RecoveryCodeCount)
	digests := make([]string, len(codes))
	for i := range codes {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, nil, domain.ErrDependencyUnavailable
		}
		codes[i] = hex.EncodeToString(entropy[:])
		digests[i] = s.factorCipher.Digest("recovery:" + string(pending.UserID) + ":" + codes[i])
	}
	account.Factor, account.LastStep, account.RecoveryDigests = factor, step, digests
	return account, codes, nil
}
