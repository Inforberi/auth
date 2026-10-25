package service

import (
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

// IntrospectionFactory owns client identity, verifier and shared admission, but no SQL repository.
type IntrospectionFactory struct{ template Introspection }

func NewIntrospectionFactory(limiter IntrospectionLimiter, keys *authjwt.PublicKeys, cfg IntrospectionConfig, catalog accesssettings.Catalog) (*IntrospectionFactory, error) {
	if limiter == nil || cfg.ConsumerPerMinute < 1 || cfg.ConsumerPerMinute > 1_000_000 || cfg.ProjectPerMinute < 1 || cfg.ProjectPerMinute > 1_000_000 {
		return nil, authjwt.ErrConfiguration
	}
	resources, err := audiencePolicies(cfg.Resources, catalog)
	if err != nil {
		return nil, err
	}
	clients, err := introspectionClients(cfg.Clients, resources)
	if err != nil {
		return nil, err
	}
	policies := make([]authjwt.Expectations, 0, len(resources))
	for audience, resource := range resources {
		policies = append(policies, authjwt.Expectations{Issuer: cfg.Issuer, Audience: audience, Mode: resource.mode})
	}
	verifier, err := authjwt.NewIssuerVerifier(policies, keys)
	if err != nil {
		return nil, err
	}
	cfg.Resources, cfg.Clients = nil, nil
	return &IntrospectionFactory{template: Introspection{verifier: verifier, limiter: limiter, resources: resources, clients: clients, config: cfg, admission: make(chan struct{}, 32)}}, nil
}

func (f *IntrospectionFactory) Bind(repo IntrospectionRepository) (*Introspection, error) {
	if f == nil || repo == nil {
		return nil, authjwt.ErrConfiguration
	}
	service := f.template
	service.repo = repo
	return &service, nil
}

func (f *IntrospectionFactory) Authenticate(id, secret string) (*IntrospectionClient, bool) {
	if f == nil {
		return nil, false
	}
	return f.template.Authenticate(id, secret)
}
