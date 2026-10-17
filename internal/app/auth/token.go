package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type tokenApp struct {
	service *service.Service
	handler *tokenhttp.Handler
	native  *tokenhttp.NativeHandler
}

func assembleTokens(ctx context.Context, pool *pgxpool.Pool, base *redis.Client, deployment *config.Config, login nativeLoginDependencies, catalog accesssettings.Catalog, root string, owned *resources, log *zap.Logger) (tokenApp, error) {
	native, err := deployment.NativeJWTPolicy()
	if err != nil {
		return tokenApp{}, err
	}
	cfg := deployment.JWT
	if !cfg.Enabled {
		return tokenApp{}, nil
	}
	definitions, err := settings.LoadResources(cfg.ResourceFile)
	if err != nil {
		return tokenApp{}, err
	}
	signer, err := signing.Load(signing.KeyConfig{
		Enabled: true, Issuer: cfg.Issuer, SigningKeyID: cfg.SigningKeyID,
		PrivateKeyFile: cfg.PrivateKeyFile, KeySetFile: cfg.KeySetFile,
	})
	if err != nil {
		return tokenApp{}, err
	}
	digest, err := secretbox.NewScoped(root, "jwt-issuance-limits:v1")
	if err != nil {
		return tokenApp{}, err
	}
	// Retry policy is client-global in go-redis. This bounded pool does not change existing Auth clients.
	opts := *base.Options()
	opts.MaxRetries, opts.ContextTimeoutEnabled = -1, true
	opts.PoolSize, opts.MaxActiveConns, opts.MinIdleConns, opts.MaxIdleConns = 8, 8, 0, 8
	opts.PoolTimeout, opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = time.Second, time.Second, time.Second, time.Second
	client := redis.NewClient(&opts)
	owned.add(func() {
		if err := client.Close(); err != nil {
			log.Warn("JWT Redis client close failed")
		}
	})
	limiter, err := tokenredis.New(client, digest, tokenredis.Limits{
		ActorPerMinute:   cfg.ActorPerMinute,
		SessionPerMinute: cfg.SessionPerMinute, IPPerMinute: cfg.IPPerMinute, ProjectPerMinute: cfg.ProjectPerMinute,
	})
	if err != nil {
		return tokenApp{}, err
	}
	svc, err := service.New(tokenpostgres.New(pool), signer, limiter, tokengenerate.New(), service.Config{AccessTTL: cfg.AccessTTL, Resources: definitions, Native: native}, catalog)
	if err != nil {
		return tokenApp{}, err
	}
	ready, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(ready).Err(); err != nil {
		return tokenApp{}, err
	}
	assembly := tokenApp{service: svc, handler: tokenhttp.New(svc, signer.PublicJWKS(), log)}
	assembly.native, err = assembleNativeTokens(&assembly, login.password, login.mfa, login.email, deployment, log)
	if err != nil {
		return tokenApp{}, err
	}
	return assembly, nil
}
