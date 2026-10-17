package service

import (
	"context"
	"net/netip"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type NativeInput struct {
	Proof         mfaservice.PrimaryProof `json:"-"`
	Audience      string
	Scope         []accessdomain.PermissionKey
	UserAgent, IP string
}

type NativeParams struct {
	Input                           NativeInput
	Policy                          NativePolicy
	Mode                            string
	LedgerVerifier, RefreshVerifier string `json:"-"`
}

type NativeSigner func(context.Context, ExchangeInput, string, SessionProof) (*signing.SignedToken, error)

type nativeCredentials struct{ ledgerVerifier, refresh, refreshVerifier string }

// IssueNative consumes only a server-owned password proof. Required MFA remains fail-closed
// until native-purpose challenges can complete issuance in the same transaction.
func (s *Service) IssueNative(ctx context.Context, input NativeInput) (*RefreshResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.native == nil {
		return nil, domain.ErrNativeDisabled
	}
	if !mfaservice.ValidPrimary(input.Proof) || input.Proof.Administrative || input.Proof.Method != "password" || len(input.UserAgent) > 512 {
		return nil, domain.ErrInvalidRequest
	}
	ip, err := netip.ParseAddr(input.IP)
	if err != nil || ip.Zone() != "" {
		return nil, domain.ErrInvalidRequest
	}
	input.IP = ip.Unmap().String()
	resource, scope, err := s.requestedResource(input.Audience, input.Scope)
	if err != nil {
		return nil, err
	}
	input.Scope = scope
	select {
	case s.admission <- struct{}{}:
	default:
		return nil, authjwt.ErrBusy
	}
	defer func() { <-s.admission }()
	// Actor/project budgets are shared with exchange; no client-controlled family key is allocated.
	if err := s.limiter.AllowNative(ctx, input.Proof.UserID, input.IP); err != nil {
		return nil, err
	}
	credentials, err := s.newNativeCredentials()
	if err != nil {
		return nil, err
	}
	result, err := s.repo.IssueNative(ctx, NativeParams{Input: input, Policy: *s.native, Mode: resource.mode, LedgerVerifier: credentials.ledgerVerifier, RefreshVerifier: credentials.refreshVerifier}, s.signSession)
	if err != nil {
		return nil, err
	}
	if result == nil || result.ExchangeResult == nil || result.SignedToken == nil || result.Raw == "" {
		return nil, domain.ErrUnavailable
	}
	result.RefreshToken = credentials.refresh
	return result, nil
}

func (s *Service) newNativeCredentials() (nativeCredentials, error) {
	var credentials nativeCredentials
	ledger, err := s.tokens.GenerateToken()
	if err != nil {
		return credentials, err
	}
	credentials.ledgerVerifier, err = domain.RefreshVerifier(ledger)
	if err != nil {
		return credentials, err
	}
	credentials.refresh, err = s.tokens.GenerateToken()
	if err != nil {
		return credentials, err
	}
	credentials.refreshVerifier, err = domain.RefreshVerifier(credentials.refresh)
	if err != nil {
		return credentials, err
	}
	if credentials.ledgerVerifier == credentials.refreshVerifier {
		return credentials, domain.ErrUnavailable
	}
	return credentials, nil
}
