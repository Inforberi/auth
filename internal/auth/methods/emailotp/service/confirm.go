package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type ConfirmInput struct {
	Code      string
	Binding   string
	UserAgent string
	IP        string
}

type AuthenticatedAccount struct {
	accountdomain.User
	EmailID accountdomain.AddressID
}

func (s *Service) Confirm(ctx context.Context, input ConfirmInput) (*sessionservice.CreatedSession, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrDisabled
	}
	if !domain.ValidBinding(input.Binding) || !domain.ValidCode(input.Code) {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.limit(ctx, "confirm:ip:"+input.IP, 10, time.Minute); err != nil {
		return nil, err
	}
	if err := s.limit(ctx, "confirm:project", s.cfg.ConfirmGlobalLimit, time.Minute); err != nil {
		return nil, err
	}
	if s.cfg.CheckPolicy != nil {
		if err := s.cfg.CheckPolicy(ctx); err != nil {
			return nil, err
		}
	}
	consumeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	user, err := s.repo.Consume(consumeCtx, s.cipher.Digest("binding:"+input.Binding), s.cipher.Digest("code:"+input.Binding+":"+input.Code))
	stop()
	if err != nil {
		return nil, err
	}
	// Consumption stays one-time even if the subsequent session commit or response fails.
	return s.sessions.BeginLogin(ctx, mfaservice.PrimaryProof{
		UserID: user.ID, AuthVersion: int64(user.AuthVersion),
		Method: "emailotp", Reference: string(user.EmailID), VerifiedAt: time.Now().UTC(),
	}, input.UserAgent, input.IP)
}
