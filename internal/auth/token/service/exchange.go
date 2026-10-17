package service

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type ExchangeInput struct {
	Actor     accessservice.Principal
	SessionID string
	Audience  string
	Scope     []accessdomain.PermissionKey
	IP        string
}

type SessionProof struct {
	AuthVersion   int64
	Deadline      time.Time
	VerifiedAt    time.Time
	MFAVerifiedAt *time.Time
	Method        string
	Now           time.Time
}

type ExchangeResult struct {
	*signing.SignedToken
	Audience string
	Scope    []accessdomain.PermissionKey
}

func (s *Service) Exchange(ctx context.Context, input ExchangeInput) (*ExchangeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input.Actor.Validate() != nil || sessiondomain.ValidateID(input.SessionID) != nil {
		return nil, sessiondomain.ErrSessionNotFound
	}
	ip, err := netip.ParseAddr(input.IP)
	if err != nil || ip.Zone() != "" {
		return nil, domain.ErrInvalidRequest
	}
	input.IP = ip.Unmap().String()
	resource, ok := s.resources[input.Audience]
	if !ok || len(input.Scope) == 0 || len(input.Scope) > 64 {
		return nil, domain.ErrInvalidRequest
	}
	input.Scope = slices.Clone(input.Scope)
	slices.Sort(input.Scope)
	keys := make([]string, len(input.Scope))
	for i, key := range input.Scope {
		if !resource.permissions[key] || i > 0 && key == input.Scope[i-1] {
			return nil, domain.ErrForbidden
		}
		keys[i] = string(key)
	}
	scope := strings.Join(keys, " ")
	if len(scope) > 2048 {
		return nil, domain.ErrInvalidRequest
	}
	select {
	case s.admission <- struct{}{}:
	default:
		return nil, authjwt.ErrBusy
	}
	defer func() { <-s.admission }()
	if err := s.limiter.Allow(ctx, input); err != nil {
		return nil, err
	}
	issued, err := s.repo.Exchange(ctx, input, resource.mode, func(ctx context.Context, proof SessionProof) (*signing.SignedToken, error) {
		deadline := proof.Now.Add(s.ttl)
		if proof.Deadline.Before(deadline) {
			deadline = proof.Deadline
		}
		method := map[string]string{"password": "pwd", "emailotp": "emailotp", "oidc": "oidc"}[proof.Method]
		claims := authjwt.Claims{
			Subject: string(input.Actor.UserID), SessionID: input.SessionID, Audience: input.Audience,
			AuthVersion: proof.AuthVersion, Scope: scope, Mode: resource.mode, ExpiresAt: deadline.Unix(),
			AuthTime: proof.VerifiedAt.Unix(), Methods: []string{method},
		}
		if proof.MFAVerifiedAt != nil {
			verified := proof.MFAVerifiedAt.Unix()
			claims.MFATime = &verified
			// The session ledger retains the fact of MFA, not the individual TOTP/recovery mechanism.
			claims.Methods = append(claims.Methods, "mfa")
		}
		return s.signer.Sign(ctx, claims, proof.Now)
	})
	if err != nil {
		return nil, err
	}
	return &ExchangeResult{SignedToken: issued, Audience: input.Audience, Scope: input.Scope}, nil
}
