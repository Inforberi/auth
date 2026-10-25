package auth

import (
	"context"

	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func (p *ProjectEmailOTP) Request(ctx context.Context, email, ip string) (*otpservice.RequestedCode, error) {
	if !p.cfg.OTP.Enabled {
		return nil, otpdomain.ErrDisabled
	}
	var result *otpservice.RequestedCode
	err := p.use(ctx, func(ctx context.Context, service *otpservice.Service) error {
		var err error
		result, err = service.Request(ctx, email, ip)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectEmailOTP) Confirm(ctx context.Context, input otpservice.ConfirmInput) (*sessionservice.CreatedSession, error) {
	if !p.cfg.OTP.Enabled {
		return nil, otpdomain.ErrDisabled
	}
	var result *sessionservice.CreatedSession
	err := p.use(ctx, func(ctx context.Context, service *otpservice.Service) error {
		var err error
		result, err = service.Confirm(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectEmailOTP) RequestReauthentication(ctx context.Context, proof mfaservice.Proof, email, ip string) (*otpservice.RequestedCode, error) {
	if !p.cfg.OTP.ReauthenticationEnabled {
		return nil, otpdomain.ErrDisabled
	}
	var result *otpservice.RequestedCode
	err := p.use(ctx, func(ctx context.Context, service *otpservice.Service) error {
		var err error
		result, err = service.RequestReauthentication(ctx, proof, email, ip)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectEmailOTP) ConfirmReauthentication(ctx context.Context, input otpservice.ReauthenticationInput) (*otpservice.ReauthenticatedSession, error) {
	if !p.cfg.OTP.ReauthenticationEnabled {
		return nil, otpdomain.ErrDisabled
	}
	var result *otpservice.ReauthenticatedSession
	err := p.use(ctx, func(ctx context.Context, service *otpservice.Service) error {
		var err error
		result, err = service.ConfirmReauthentication(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
