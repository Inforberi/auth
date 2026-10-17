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
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func assembleTokens(ctx context.Context, pool *pgxpool.Pool, base *redis.Client, cfg settings.Config, catalog accesssettings.Catalog, root string, owned *resources, log *zap.Logger) (*tokenhttp.Handler, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	definitions, err := settings.LoadResources(cfg.ResourceFile)
	if err != nil {
		return nil, err
	}
	signer, err := signing.Load(signing.KeyConfig{
		Enabled: true, Issuer: cfg.Issuer, SigningKeyID: cfg.SigningKeyID,
		PrivateKeyFile: cfg.PrivateKeyFile, KeySetFile: cfg.KeySetFile,
	})
	if err != nil {
		return nil, err
	}
	digest, err := secretbox.NewScoped(root, "jwt-issuance-limits:v1")
	if err != nil {
		return nil, err
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
		return nil, err
	}
	svc, err := service.New(tokenpostgres.New(pool), signer, limiter, tokengenerate.New(), service.Config{AccessTTL: cfg.AccessTTL, Resources: definitions}, catalog)
	if err != nil {
		return nil, err
	}
	ready, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(ready).Err(); err != nil {
		return nil, err
	}
	return tokenhttp.New(svc, signer.PublicJWKS(), log), nil
}
