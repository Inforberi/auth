package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type Repository interface {
	Exchange(context.Context, ExchangeInput, string, func(context.Context, SessionProof) (*signing.SignedToken, error)) (*signing.SignedToken, error)
	ResolveRefresh(context.Context, string) (RefreshBinding, error)
	LogoutRefresh(context.Context, RefreshBinding, string) error
	Refresh(context.Context, RefreshParams, func(context.Context, RefreshProof) (*ExchangeResult, error)) (*RefreshResult, error)
	IssueNative(context.Context, NativeParams, NativeSigner) (*RefreshResult, error)
	CompleteNativeMFA(context.Context, NativeMFAParams, func(mfaservice.NativeTarget) (string, error), NativeSigner) (*RefreshResult, error)
}

type Signer interface {
	Sign(context.Context, authjwt.Claims, time.Time) (*signing.SignedToken, error)
}

type Limiter interface {
	Allow(context.Context, ExchangeInput) error
	AllowCredentialLookup(context.Context, string) error
	AllowNative(context.Context, accountdomain.UserID, string) error
}

type TokenGenerator interface{ GenerateToken(...int) (string, error) }

type Service struct {
	repo      Repository
	signer    Signer
	limiter   Limiter
	tokens    TokenGenerator
	resources map[string]resourcePolicy
	ttl       time.Duration
	admission chan struct{}
	native    *NativePolicy
}

func New(repo Repository, signer Signer, limiter Limiter, tokens TokenGenerator, cfg Config, catalog settings.Catalog) (*Service, error) {
	factory, err := NewFactory(signer, limiter, tokens, cfg, catalog)
	if err != nil {
		return nil, err
	}
	return factory.Bind(repo)
}
