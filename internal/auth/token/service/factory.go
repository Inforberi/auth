package service

import (
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

// Factory shares immutable policy and admission across short-lived repository bindings.
type Factory struct{ template Service }

func NewFactory(signer Signer, limiter Limiter, tokens TokenGenerator, cfg Config, catalog settings.Catalog) (*Factory, error) {
	resources, err := resourcePolicies(cfg, catalog)
	if err != nil {
		return nil, err
	}
	if signer == nil || limiter == nil || tokens == nil {
		return nil, authjwt.ErrConfiguration
	}
	s := Service{signer: signer, limiter: limiter, tokens: tokens, resources: resources, ttl: cfg.AccessTTL, admission: make(chan struct{}, 8)}
	if cfg.Native != nil {
		if err := cfg.Native.Validate(); err != nil {
			return nil, err
		}
		policy := *cfg.Native
		s.native = &policy
	}
	return &Factory{template: s}, nil
}

func (f *Factory) Bind(repo Repository) (*Service, error) {
	if f == nil || repo == nil {
		return nil, authjwt.ErrConfiguration
	}
	service := f.template
	service.repo = repo
	return &service, nil
}
