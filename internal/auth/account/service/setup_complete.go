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
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
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
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != input.Token || !domain.ValidEmailBindingCode(input.EmailCode) || !mfadomain.ValidCode(input.TOTP) {
		return nil, domain.ErrSetupInvalid
	}
	codes := make([]string, mfadomain.RecoveryCodeCount)
	for i := range codes {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, domain.ErrDependencyUnavailable
		}
		codes[i] = hex.EncodeToString(entropy[:])
	}
	err = s.repo.CompleteSetup(ctx, tokenDigest(input.OperatorSecret), s.cipher.Digest("request:"+input.Token), func(encrypted []byte, now time.Time) (*domain.SetupAccount, error) {
		plain, err := s.cipher.Open(encrypted)
		if err != nil {
			return nil, domain.ErrDependencyUnavailable
		}
		defer clear(plain)
		var pending setupPayload
		if err := json.Unmarshal(plain, &pending); err != nil {
			return nil, domain.ErrDependencyUnavailable
		}
		if subtle.ConstantTimeCompare([]byte(pending.EmailDigest), []byte(s.cipher.Digest("email:"+input.Token+":"+input.EmailCode))) != 1 {
			return nil, domain.ErrSetupInvalid
		}
		step, err := s.code.Match(pending.Secret, input.TOTP, now, -1)
		if errors.Is(err, mfadomain.ErrInvalidCode) {
			return nil, domain.ErrSetupInvalid
		}
		if err != nil {
			return nil, domain.ErrDependencyUnavailable
		}
		factor, err := s.factorCipher.Seal([]byte(string(pending.UserID) + "\x00" + pending.Secret))
		if err != nil {
			return nil, domain.ErrDependencyUnavailable
		}
		digests := make([]string, len(codes))
		for i, code := range codes {
			digests[i] = s.factorCipher.Digest("recovery:" + string(pending.UserID) + ":" + code)
		}
		return &domain.SetupAccount{UserID: pending.UserID, Email: pending.Email, PasswordHash: pending.PasswordHash, Factor: factor, LastStep: step, RecoveryDigests: digests}, nil
	})
	if err != nil {
		return nil, err
	}
	return &SetupCompleted{RecoveryCodes: codes}, nil
}
