package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type activationRepository interface {
	CheckInvitation(context.Context, string) error
	ActivateInvitation(context.Context, string, string) error
}

type ActivationService struct {
	repo     activationRepository
	recovery *RecoveryService
	cfg      accountservice.InvitationConfig
}

func NewActivation(repo activationRepository, recovery *RecoveryService, cfg accountservice.InvitationConfig) *ActivationService {
	return &ActivationService{repo: repo, recovery: recovery, cfg: cfg}
}

func (s *ActivationService) Activate(ctx context.Context, token, password, confirmation, ip string) error {
	if !s.cfg.Enabled {
		return accountdomain.ErrProvisionDisabled
	}
	if len(token) != 43 {
		return accountdomain.ErrInvalidInvitation
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return accountdomain.ErrInvalidInvitation
	}
	if password != confirmation {
		return domain.ErrPasswordConfirmation
	}
	if err := domain.ValidatePassword(password); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.recovery.limit(ctx, "activation-ip:"+ip, 10, time.Minute); err != nil {
		return err
	}
	if err := s.recovery.limit(ctx, "activation-global", s.cfg.ActivationGlobalLimit, time.Minute); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])
	// Preflight avoids hashing invalid tokens; the transaction rechecks current authority after hashing.
	if err := s.repo.CheckInvitation(ctx, digest); err != nil {
		return err
	}
	hash, err := s.recovery.hash.GenerateHash(ctx, []byte(password))
	if err != nil {
		return err
	}
	return s.repo.ActivateInvitation(ctx, digest, hash)
}
