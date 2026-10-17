package service

import (
	"context"
	"net/netip"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type RefreshInput struct {
	Token string `json:"-"`
	IP    string
}

// RefreshBinding is only a budget hint. The transaction rechecks SQL authority.
type RefreshBinding struct {
	Actor     accessservice.Principal
	SessionID string
}

type RefreshParams struct {
	Binding     RefreshBinding
	Verifier    string `json:"-"`
	Replacement string `json:"-"`
}

type RefreshProof struct {
	SessionProof
	Family       domain.RefreshFamily
	GrantedScope []accessdomain.PermissionKey
}

type RefreshResult struct {
	*ExchangeResult
	RefreshToken     string `json:"-"`
	RefreshExpiresAt time.Time
}

func (s *Service) Refresh(ctx context.Context, input RefreshInput) (*RefreshResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verifier, err := domain.RefreshVerifier(input.Token)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(input.IP)
	if err != nil || ip.Zone() != "" {
		return nil, domain.ErrInvalidRequest
	}
	select {
	case s.admission <- struct{}{}:
	default:
		return nil, authjwt.ErrBusy
	}
	defer func() { <-s.admission }()
	address := ip.Unmap().String()
	if err := s.limiter.AllowRefreshLookup(ctx, address); err != nil {
		return nil, err
	}
	binding, err := s.repo.ResolveRefresh(ctx, verifier)
	if err != nil {
		return nil, err
	}
	if err := s.limiter.Allow(ctx, ExchangeInput{Actor: binding.Actor, SessionID: binding.SessionID, IP: address}); err != nil {
		return nil, err
	}
	raw, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	replacement, err := domain.RefreshVerifier(raw)
	if err != nil {
		return nil, err
	}
	result, err := s.repo.Refresh(ctx, RefreshParams{Binding: binding, Verifier: verifier, Replacement: replacement},
		func(ctx context.Context, proof RefreshProof) (*ExchangeResult, error) {
			return s.signRefresh(ctx, binding, proof)
		})
	if err != nil {
		return nil, err
	}
	if result == nil || result.ExchangeResult == nil || result.SignedToken == nil || result.Raw == "" {
		return nil, domain.ErrUnavailable
	}
	result.RefreshToken = raw
	return result, nil
}

func (s *Service) signRefresh(ctx context.Context, binding RefreshBinding, proof RefreshProof) (*ExchangeResult, error) {
	resource, ok := s.resources[proof.Family.Audience]
	if !ok {
		return nil, domain.ErrForbidden
	}
	scope := make([]accessdomain.PermissionKey, 0, len(proof.GrantedScope))
	for _, key := range proof.GrantedScope {
		if resource.permissions[key] {
			scope = append(scope, key)
		}
	}
	if len(scope) == 0 {
		return nil, domain.ErrForbidden
	}
	issued, err := s.signSession(ctx, ExchangeInput{Actor: binding.Actor, SessionID: binding.SessionID, Audience: proof.Family.Audience, Scope: scope}, resource.mode, proof.SessionProof)
	if err != nil {
		return nil, err
	}
	return &ExchangeResult{SignedToken: issued, Audience: proof.Family.Audience, Scope: scope, Mode: resource.mode}, nil
}
