package service

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func (s *Service) Logout(ctx context.Context, input RefreshInput) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	verifier, err := domain.RefreshVerifier(input.Token)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(input.IP)
	if err != nil || ip.Zone() != "" {
		return domain.ErrInvalidRequest
	}
	select {
	case s.admission <- struct{}{}:
	default:
		return authjwt.ErrBusy
	}
	defer func() { <-s.admission }()
	address := ip.Unmap().String()
	if err := s.limiter.AllowCredentialLookup(ctx, address); err != nil {
		return err
	}
	binding, err := s.repo.ResolveRefresh(ctx, verifier)
	if errors.Is(err, domain.ErrInvalidRefresh) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.limiter.Allow(ctx, ExchangeInput{Actor: binding.Actor, SessionID: binding.SessionID, IP: address}); err != nil {
		return err
	}
	err = s.repo.LogoutRefresh(ctx, binding, verifier)
	if errors.Is(err, domain.ErrInvalidRefresh) {
		return nil
	}
	return err
}
