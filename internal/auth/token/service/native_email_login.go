package service

import (
	"context"
	"net/netip"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	emailservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type NativeEmailOTP interface {
	RequestNative(context.Context, string, string, mfaservice.NativeTarget) (*emailservice.RequestedCode, error)
	AuthenticateNative(context.Context, emailservice.ConfirmInput) (*emailservice.NativeAuthentication, error)
}

type NativeEmailLogin struct {
	login *NativeLogin
	email NativeEmailOTP
}

func NewNativeEmailLogin(login *NativeLogin, email NativeEmailOTP) (*NativeEmailLogin, error) {
	if login == nil || email == nil {
		return nil, authjwt.ErrConfiguration
	}
	return &NativeEmailLogin{login: login, email: email}, nil
}

func (s *NativeEmailLogin) Request(ctx context.Context, email, ip, audience string, scope []accessdomain.PermissionKey) (*emailservice.RequestedCode, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, bound, err := s.login.tokens.requestedResource(audience, scope)
	if err != nil {
		return nil, err
	}
	select {
	case s.login.tokens.admission <- struct{}{}:
	default:
		return nil, authjwt.ErrBusy
	}
	defer func() { <-s.login.tokens.admission }()
	return s.email.RequestNative(ctx, email, ip, mfaservice.NativeTarget{Audience: audience, Scope: bound})
}

func (s *NativeEmailLogin) Confirm(ctx context.Context, input emailservice.ConfirmInput) (*NativeLoginResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	verified, err := s.authenticate(ctx, input)
	if err != nil {
		return nil, err
	}
	// The consumed code cannot be retried if issuance fails. Target comes only from locked SQL.
	return s.login.Begin(ctx, NativeInput{
		Proof: verified.Proof, Audience: verified.Target.Audience,
		Scope: verified.Target.Scope, IP: input.IP, UserAgent: input.UserAgent,
	})
}

func (s *NativeEmailLogin) authenticate(ctx context.Context, input emailservice.ConfirmInput) (*emailservice.NativeAuthentication, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(input.IP)
	if err != nil || address.Zone() != "" {
		return nil, domain.ErrInvalidRequest
	}
	input.IP = address.Unmap().String()
	select {
	case s.login.tokens.admission <- struct{}{}:
	default:
		return nil, authjwt.ErrBusy
	}
	defer func() { <-s.login.tokens.admission }()
	if err := s.login.tokens.limiter.AllowCredentialLookup(ctx, input.IP); err != nil {
		return nil, err
	}
	return s.email.AuthenticateNative(ctx, input)
}
