package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func newProjectIntrospection(limiter tokenservice.IntrospectionLimiter, public []byte, cfg ProjectTokenConfig) (*tokenservice.IntrospectionFactory, error) {
	if cfg.Introspection == nil {
		return nil, nil
	}
	keys, err := authjwt.ParsePublicKeys(public)
	if err != nil {
		return nil, err
	}
	return tokenservice.NewIntrospectionFactory(limiter, keys, tokenservice.IntrospectionConfig{
		Issuer: cfg.Issuer, Resources: cfg.Tokens.Resources, Clients: cfg.Introspection.Clients,
		ConsumerPerMinute: cfg.Introspection.ConsumerPerMinute, ProjectPerMinute: cfg.Introspection.ProjectPerMinute,
	}, cfg.Catalog)
}

// Authenticate checks only the local consumer manifest; Inspect owns the current project/SQL decision.
func (p *ProjectTokens) Authenticate(id, secret string) (*tokenservice.IntrospectionClient, bool) {
	if !p.cfg.Enabled {
		return nil, false
	}
	return p.introspection.Authenticate(id, secret)
}

func (p *ProjectTokens) Inspect(ctx context.Context, client *tokenservice.IntrospectionClient, raw string) (tokenservice.IntrospectionResult, error) {
	var result tokenservice.IntrospectionResult
	if p.introspection == nil {
		return result, tokendomain.ErrUnavailable
	}
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, _ *tokenservice.Service) error {
		service, err := p.introspection.Bind(tokenpostgres.New(pool))
		if err != nil {
			return err
		}
		result, err = service.Inspect(ctx, client, raw)
		return err
	})
	if err != nil {
		return tokenservice.IntrospectionResult{}, err
	}
	return result, nil
}
