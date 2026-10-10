package service

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type ProtectedRecoveryRepo interface {
	ProtectedRecoveryHash(context.Context, string) (string, error)
	RecoverProtectedAccount(context.Context, string, string, string) error
}

type ProtectedRecoveryService struct {
	repo     ProtectedRecoveryRepo
	recovery *RecoveryService
}

func NewProtectedRecovery(repo ProtectedRecoveryRepo, recovery *RecoveryService) *ProtectedRecoveryService {
	return &ProtectedRecoveryService{repo: repo, recovery: recovery}
}

func (s *ProtectedRecoveryService) Recover(ctx context.Context, token, password, confirmation, ip string) error {
	if len(token) != 43 {
		return accountdomain.ErrInvalidAccountRecovery
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return accountdomain.ErrInvalidAccountRecovery
	}
	if password != confirmation {
		return domain.ErrPasswordConfirmation
	}
	if err := domain.ValidatePassword(password); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.recovery.limit(ctx, "protected-recovery-ip:"+ip, 10, time.Minute); err != nil {
		return err
	}
	// Share the process hash budget and distributed reset budget, rather than create another pool.
	if err := s.recovery.limit(ctx, "reset-global", 100, time.Minute); err != nil {
		return err
	}
	digest := resetDigest(token)
	expectedHash, err := s.repo.ProtectedRecoveryHash(ctx, digest)
	if err != nil {
		return err
	}
	select {
	case s.recovery.hashSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.recovery.hashSlots }()
	err = s.recovery.hash.Compare(password, expectedHash)
	if err == nil {
		return domain.ErrSamePassword
	}
	if !errors.Is(err, domain.ErrPasswordHashMismatch) {
		return err
	}
	hash, err := s.recovery.hash.GenerateHash([]byte(password))
	if err != nil {
		return err
	}
	return s.repo.RecoverProtectedAccount(ctx, digest, expectedHash, hash)
}
