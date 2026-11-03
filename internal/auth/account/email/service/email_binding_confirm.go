package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (s *EmailBindingService) Confirm(ctx context.Context, proof mfaservice.Proof, code, ip string) error {
	if !s.cfg.Enabled {
		return domain.ErrEmailBindingDisabled
	}
	if err := proof.Validate(); err != nil {
		return domain.ErrFreshAuthRequired
	}
	if !domain.ValidEmailBindingCode(code) {
		return domain.ErrInvalidEmailBinding
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, limit := range []struct {
		key   string
		count int
	}{
		{"confirm:ip:" + ip, 20}, {"confirm:user:" + string(proof.UserID), 5}, {"confirm:project", s.cfg.ConfirmationsPerMinute},
	} {
		if err := s.admit(ctx, limit.key, limit.count, time.Minute); err != nil {
			return err
		}
	}
	return s.repo.ConfirmEmailBinding(ctx, proof, s.verifier(proof.UserID, code))
}
