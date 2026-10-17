package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type refreshRepo struct {
	exchangeRepo
	binding               RefreshBinding
	proof                 RefreshProof
	lookupErr, refreshErr error
	lookups, rotations    int
	params                RefreshParams
}

func (r *refreshRepo) ResolveRefresh(_ context.Context, _ string) (RefreshBinding, error) {
	r.lookups++
	return r.binding, r.lookupErr
}

func (r *refreshRepo) Refresh(ctx context.Context, p RefreshParams, sign func(context.Context, RefreshProof) (*ExchangeResult, error)) (*RefreshResult, error) {
	r.rotations++
	r.params = p
	if r.refreshErr != nil {
		return nil, r.refreshErr
	}
	access, err := sign(ctx, r.proof)
	if err != nil {
		return nil, err
	}
	return &RefreshResult{ExchangeResult: access, RefreshExpiresAt: r.proof.Family.AbsoluteExpiresAt}, nil
}

type refreshLimiter struct {
	exchangeLimiter
	lookupErr error
	lookups   int
	ip        string
}

func (l *refreshLimiter) AllowRefreshLookup(_ context.Context, ip string) error {
	l.lookups++
	l.ip = ip
	return l.lookupErr
}

func refreshServiceFixture(t *testing.T) (*Service, *refreshRepo, *exchangeSigner, *refreshLimiter, RefreshInput) {
	t.Helper()
	svc, exchange, signer, _, input := exchangeFixture(t)
	raw, err := tokengenerate.New().GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	repo := &refreshRepo{binding: RefreshBinding{Actor: input.Actor, SessionID: input.SessionID}, proof: RefreshProof{
		SessionProof: exchange.proof, Family: domain.RefreshFamily{SessionID: input.SessionID, Audience: input.Audience, Scope: []accessdomain.PermissionKey{"orders.read"}, AbsoluteExpiresAt: exchange.proof.Now.Add(2 * time.Hour)}, GrantedScope: []accessdomain.PermissionKey{"orders.read"},
	}}
	limiter := &refreshLimiter{}
	svc.repo, svc.limiter = repo, limiter
	return svc, repo, signer, limiter, RefreshInput{Token: raw, IP: input.IP}
}

func TestRefreshClaimsAndSecretBoundary(t *testing.T) {
	svc, repo, signer, limiter, input := refreshServiceFixture(t)
	mfa := repo.proof.VerifiedAt.Add(time.Minute)
	repo.proof.MFAVerifiedAt = &mfa
	repo.proof.Deadline = repo.proof.Now.Add(45 * time.Second)
	result, err := svc.Refresh(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := domain.RefreshVerifier(result.RefreshToken)
	if err != nil || verifier != repo.params.Replacement || result.RefreshToken == input.Token || repo.params.Verifier != tokengenerate.New().Hash(input.Token) {
		t.Fatal("raw/hash boundary", err)
	}
	claims := signer.claims
	if claims.Subject != string(repo.binding.Actor.UserID) || claims.SessionID != repo.binding.SessionID || claims.Audience != "orders" || claims.Scope != "orders.read" || claims.Mode != authjwt.Strict || claims.AuthVersion != repo.proof.AuthVersion || claims.ExpiresAt != repo.proof.Deadline.Unix() || claims.AuthTime != repo.proof.VerifiedAt.Unix() || claims.MFATime == nil || *claims.MFATime != mfa.Unix() {
		t.Fatal("non-authoritative claims", claims)
	}
	if !result.RefreshExpiresAt.Equal(repo.proof.Family.AbsoluteExpiresAt) || limiter.ip != "192.0.2.1" || limiter.lookups != 1 || limiter.calls != 1 {
		t.Fatal("binding/budget/deadline changed")
	}
	delete(svc.resources["orders"].permissions, "orders.read")
	if result, err := svc.Refresh(t.Context(), input); result != nil || !errors.Is(err, domain.ErrForbidden) {
		t.Fatal("resource scope not intersected", err)
	}
}

func TestRefreshAdmissionAndFailures(t *testing.T) {
	for _, test := range []struct {
		name               string
		change             func(*Service, *refreshRepo, *exchangeSigner, *refreshLimiter, *RefreshInput)
		want               error
		lookups, rotations int
	}{
		{"malformed", func(_ *Service, _ *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, i *RefreshInput) {
			i.Token = "bad"
		}, domain.ErrInvalidRefresh, 0, 0},
		{"JWT", func(_ *Service, _ *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, i *RefreshInput) {
			i.Token = strings.Repeat("a", 42) + "."
		}, domain.ErrInvalidRefresh, 0, 0},
		{"IP", func(_ *Service, _ *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, i *RefreshInput) { i.IP = "bad" }, domain.ErrInvalidRequest, 0, 0},
		{"zone", func(_ *Service, _ *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, i *RefreshInput) {
			i.IP = "fe80::1%en0"
		}, domain.ErrInvalidRequest, 0, 0},
		{"busy", func(s *Service, _ *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, _ *RefreshInput) {
			for range cap(s.admission) {
				s.admission <- struct{}{}
			}
		}, authjwt.ErrBusy, 0, 0},
		{"prelookup unavailable", func(_ *Service, _ *refreshRepo, _ *exchangeSigner, l *refreshLimiter, _ *RefreshInput) {
			l.lookupErr = domain.ErrUnavailable
		}, domain.ErrUnavailable, 0, 0},
		{"prelookup rate", func(_ *Service, _ *refreshRepo, _ *exchangeSigner, l *refreshLimiter, _ *RefreshInput) {
			l.lookupErr = domain.ErrRateLimited
		}, domain.ErrRateLimited, 0, 0},
		{"unknown", func(_ *Service, r *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, _ *RefreshInput) {
			r.lookupErr = domain.ErrInvalidRefresh
		}, domain.ErrInvalidRefresh, 1, 0},
		{"family budget", func(_ *Service, _ *refreshRepo, _ *exchangeSigner, l *refreshLimiter, _ *RefreshInput) {
			l.err = domain.ErrRateLimited
		}, domain.ErrRateLimited, 1, 0},
		{"reused", func(_ *Service, r *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, _ *RefreshInput) {
			r.refreshErr = domain.ErrInvalidRefresh
		}, domain.ErrInvalidRefresh, 1, 1},
		{"sign failure", func(_ *Service, _ *refreshRepo, s *exchangeSigner, _ *refreshLimiter, _ *RefreshInput) {
			s.err = authjwt.ErrBusy
		}, authjwt.ErrBusy, 1, 1},
		{"removed audience", func(s *Service, _ *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, _ *RefreshInput) {
			delete(s.resources, "orders")
		}, domain.ErrForbidden, 1, 1},
		{"no grants", func(_ *Service, r *refreshRepo, _ *exchangeSigner, _ *refreshLimiter, _ *RefreshInput) {
			r.proof.GrantedScope = nil
		}, domain.ErrForbidden, 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, repo, signer, limiter, input := refreshServiceFixture(t)
			test.change(svc, repo, signer, limiter, &input)
			result, err := svc.Refresh(t.Context(), input)
			if result != nil || !errors.Is(err, test.want) || repo.lookups != test.lookups || repo.rotations != test.rotations {
				t.Fatal(result, err, repo.lookups, repo.rotations)
			}
		})
	}
	svc, repo, _, _, input := refreshServiceFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := svc.Refresh(ctx, input); !errors.Is(err, context.Canceled) || repo.lookups != 0 {
		t.Fatal(err)
	}
}
