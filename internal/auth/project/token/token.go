package token

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type ProjectTokens struct {
	introspection *tokenservice.IntrospectionFactory
	cfg           ProjectTokenConfig
	key           projectruntime.Key
	deps          ProjectTokenDependencies
	signer        *signing.Signer
	factory       *tokenservice.Factory
	native        *projectNative
}

func NewProjectTokens(ctx context.Context, key projectruntime.Key, cfg ProjectTokenConfig, deps ProjectTokenDependencies) (*ProjectTokens, error) {
	if err := cfg.validate(deps); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return &ProjectTokens{cfg: cfg}, nil
	}
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	if err != nil {
		return nil, err
	}
	material, err := deps.Reader.LoadSigningKey(ctx, key)
	if err != nil {
		return nil, err
	}
	var signer *signing.Signer
	err = material.Use(func(kid string, private []byte) error {
		var err error
		signer, err = signing.FromPrepared(cfg.Issuer, kid, private)
		return err
	})
	if err != nil {
		return nil, err
	}
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	if err != nil {
		return nil, err
	}
	digest, err := secretbox.ForScope(scope, configuration.EncryptionKey(), "jwt-issuance-limits:v1")
	if err != nil {
		return nil, err
	}
	limiter, err := tokenredis.NewScoped(deps.IssuanceRedis, digest, cfg.Limits, scope)
	if err != nil {
		return nil, err
	}
	factory, err := tokenservice.NewFactory(signer, limiter, tokengenerate.New(), cfg.Tokens, cfg.Catalog)
	if err != nil {
		return nil, err
	}
	introspection, err := newProjectIntrospection(limiter, signer.PublicJWKS(), cfg)
	if err != nil {
		return nil, err
	}
	native, err := newProjectNative(ctx, key, scope, configuration.EncryptionKey(), cfg, deps)
	if err != nil {
		return nil, err
	}
	if err := projectbinding.RequireCurrent(ctx, deps.Reader, key); err != nil {
		return nil, err
	}
	// Factory copies resource/native policies; retain only the runtime flags/config needed by adapters.
	cfg.Introspection = nil
	cfg.Tokens.Resources = nil
	if cfg.Tokens.Native != nil {
		policy := *cfg.Tokens.Native
		cfg.Tokens.Native = &policy
	}
	cfg.Native.EmailOTP.CheckPolicy = nil
	return &ProjectTokens{cfg: cfg, key: key, deps: deps, signer: signer, factory: factory, native: native, introspection: introspection}, nil
}

func (p *ProjectTokens) use(ctx context.Context, operation func(context.Context, *pgxpool.Pool, *tokenservice.Service) error) error {
	if !p.cfg.Enabled {
		return authjwt.ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectbinding.RequireCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		service, err := p.factory.Bind(tokenpostgres.New(pool))
		if err != nil {
			return err
		}
		if err := operation(ctx, pool, service); err != nil {
			return err
		}
		return projectbinding.RequireCurrent(ctx, p.deps.Reader, p.key)
	})
}
