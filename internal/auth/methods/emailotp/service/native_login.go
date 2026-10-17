package service

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type NativeAuthentication struct {
	Proof  mfaservice.PrimaryProof `json:"-"`
	Target mfaservice.NativeTarget
}

func (s *Service) RequestNative(ctx context.Context, email, ip string, target mfaservice.NativeTarget) (*RequestedCode, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrDisabled
	}
	if len(target.Scope) > 64 {
		return nil, domain.ErrInvalidCode
	}
	target.Scope = slices.Clone(target.Scope)
	slices.Sort(target.Scope)
	if err := target.Validate(); err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" {
		return nil, domain.ErrInvalidCode
	}
	return s.request(ctx, email, address.Unmap().String(), &target)
}

// AuthenticateNative consumes only the API-purpose code, not a browser login or reauthentication.
func (s *Service) AuthenticateNative(ctx context.Context, input ConfirmInput) (*NativeAuthentication, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	address, err := netip.ParseAddr(input.IP)
	if err != nil || address.Zone() != "" || len(input.UserAgent) > 512 {
		return nil, domain.ErrInvalidCode
	}
	input.IP = address.Unmap().String()
	if err := s.admitConfirmation(ctx, input); err != nil {
		return nil, err
	}
	return s.repo.ConsumeNative(ctx, s.cipher.Digest("native:binding:"+input.Binding), s.cipher.Digest("native:code:"+input.Binding+":"+input.Code))
}
