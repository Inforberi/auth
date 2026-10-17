package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type Repository interface {
	Exchange(context.Context, ExchangeInput, string, func(context.Context, SessionProof) (*signing.SignedToken, error)) (*signing.SignedToken, error)
}

type Signer interface {
	Sign(context.Context, authjwt.Claims, time.Time) (*signing.SignedToken, error)
}

type Limiter interface {
	Allow(context.Context, ExchangeInput) error
}

type Service struct {
	repo      Repository
	signer    Signer
	limiter   Limiter
	resources map[string]resourcePolicy
	ttl       time.Duration
	admission chan struct{}
}

func New(repo Repository, signer Signer, limiter Limiter, cfg Config, catalog settings.Catalog) (*Service, error) {
	resources, err := resourcePolicies(cfg, catalog)
	if err != nil {
		return nil, err
	}
	if repo == nil || signer == nil || limiter == nil {
		return nil, authjwt.ErrConfiguration
	}
	return &Service{repo: repo, signer: signer, limiter: limiter, resources: resources, ttl: cfg.AccessTTL, admission: make(chan struct{}, 8)}, nil
}
