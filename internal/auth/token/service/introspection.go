package service

import (
	"context"
	"errors"
	"strings"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type IntrospectionRepository interface {
	Introspect(context.Context, authjwt.Claims, []accessdomain.PermissionKey) ([]accessdomain.PermissionKey, error)
}

type IntrospectionLimiter interface {
	AllowIntrospection(context.Context, string, int, int) error
}

type IntrospectionConfig struct {
	Issuer            string
	Resources         []Resource
	Clients           []IntrospectionClientConfig
	ConsumerPerMinute int
	ProjectPerMinute  int
}

type Introspection struct {
	repo      IntrospectionRepository
	verifier  *authjwt.IssuerVerifier
	limiter   IntrospectionLimiter
	resources map[string]resourcePolicy
	clients   map[string]*IntrospectionClient
	config    IntrospectionConfig
	admission chan struct{}
}

type IntrospectionResult struct {
	Active    bool
	Issuer    string
	Subject   string
	SessionID string
	ID        string
	Audience  string
	ExpiresAt int64
	Scope     string
}

func NewIntrospection(repo IntrospectionRepository, limiter IntrospectionLimiter, keys *authjwt.PublicKeys, cfg IntrospectionConfig, catalog accesssettings.Catalog) (*Introspection, error) {
	if repo == nil || limiter == nil || cfg.ConsumerPerMinute < 1 || cfg.ConsumerPerMinute > 1_000_000 || cfg.ProjectPerMinute < 1 || cfg.ProjectPerMinute > 1_000_000 {
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
	return &Introspection{repo: repo, verifier: verifier, limiter: limiter, resources: resources, clients: clients, config: cfg, admission: make(chan struct{}, 32)}, nil
}

func (s *Introspection) Inspect(ctx context.Context, client *IntrospectionClient, raw string) (IntrospectionResult, error) {
	var inactive IntrospectionResult
	if client == nil || s.clients[client.id] != client {
		return inactive, domain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return inactive, err
	}
	select {
	case s.admission <- struct{}{}:
	default:
		return inactive, authjwt.ErrBusy
	}
	defer func() { <-s.admission }()
	if err := s.limiter.AllowIntrospection(ctx, client.id, s.config.ConsumerPerMinute, s.config.ProjectPerMinute); err != nil {
		return inactive, err
	}
	claims, err := s.verifier.VerifySignature(ctx, raw, time.Now())
	if errors.Is(err, authjwt.ErrInvalidToken) {
		return inactive, nil
	}
	if err != nil {
		return inactive, err
	}
	if !client.audiences[claims.Audience] {
		return inactive, domain.ErrForbidden
	}
	resource := s.resources[claims.Audience]
	requested := make([]accessdomain.PermissionKey, 0, 64)
	for _, key := range strings.Split(claims.Scope, " ") {
		if resource.permissions[accessdomain.PermissionKey(key)] {
			requested = append(requested, accessdomain.PermissionKey(key))
		}
	}
	if len(requested) == 0 {
		return inactive, nil
	}
	scope, err := s.repo.Introspect(ctx, claims, requested)
	if errors.Is(err, authjwt.ErrInvalidToken) {
		return inactive, nil
	}
	if err != nil {
		return inactive, err
	}
	if len(scope) == 0 || ctx.Err() != nil || claims.ExpiresAt <= time.Now().Unix() {
		return inactive, ctx.Err()
	}
	return IntrospectionResult{Active: true, Issuer: claims.Issuer, Subject: claims.Subject, SessionID: claims.SessionID, ID: claims.ID, Audience: claims.Audience, ExpiresAt: claims.ExpiresAt, Scope: permissionScope(scope)}, nil
}
