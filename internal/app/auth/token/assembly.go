package token

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/introspection/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/native/transport/http"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type App struct {
	service       *service.Service
	Handler       *tokenhttp.Handler
	Native        *tokennativehttp.NativeHandler
	Introspection *tokenintrospectionhttp.IntrospectionHandler
	Deployment    settingsdomain.TokenDeployment
}

func Assemble(ctx context.Context, scope realmscope.Scope, pool *pgxpool.Pool, base *redis.Client, deployment *config.Config, login NativeLoginDependencies, catalog accesssettings.Catalog, root string, owned interface{ Add(func()) }, log *zap.Logger) (App, error) {
	native, err := deployment.NativeJWTPolicy()
	if err != nil {
		return App{}, err
	}
	cfg := deployment.JWT
	if !cfg.Enabled {
		return App{}, nil
	}
	definitions, err := settings.LoadResources(cfg.ResourceFile)
	if err != nil {
		return App{}, err
	}
	signer, err := signing.Load(signing.KeyConfig{
		Enabled: true, Issuer: cfg.Issuer, SigningKeyID: cfg.SigningKeyID,
		PrivateKeyFile: cfg.PrivateKeyFile, KeySetFile: cfg.KeySetFile,
	})
	if err != nil {
		return App{}, err
	}
	digest, err := secretbox.ForScope(scope, root, "jwt-issuance-limits:v1")
	if err != nil {
		return App{}, err
	}
	// Retry policy is client-global in go-redis. This bounded pool does not change existing Auth clients.
	opts := *base.Options()
	opts.MaxRetries, opts.ContextTimeoutEnabled = -1, true
	opts.PoolSize, opts.MaxActiveConns, opts.MinIdleConns, opts.MaxIdleConns = 8, 8, 0, 8
	opts.PoolTimeout, opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = time.Second, time.Second, time.Second, time.Second
	client := redis.NewClient(&opts)
	owned.Add(func() {
		if err := client.Close(); err != nil {
			log.Warn("JWT Redis client close failed")
		}
	})
	limits := tokenredis.Limits{
		ActorPerMinute:   cfg.ActorPerMinute,
		SessionPerMinute: cfg.SessionPerMinute, IPPerMinute: cfg.IPPerMinute, ProjectPerMinute: cfg.ProjectPerMinute,
	}
	var introspectionBudget func(context.Context) (int, int, error)
	if load := deployment.OperationBudgetsSource; load != nil {
		limits.Source = func(ctx context.Context) (tokenredis.Limits, error) {
			p, err := load(ctx)
			return tokenredis.Limits{ActorPerMinute: p.JWTActor, SessionPerMinute: p.JWTSession, IPPerMinute: p.JWTIP, ProjectPerMinute: p.JWTGlobal}, err
		}
		introspectionBudget = func(ctx context.Context) (int, int, error) {
			p, err := load(ctx)
			return p.JWTConsumer, p.JWTIntrospection, err
		}
	}
	limiter, err := tokenredis.NewScoped(client, digest, limits, scope)
	if err != nil {
		return App{}, err
	}
	svc, err := service.New(tokenpostgres.New(pool), signer, limiter, tokengenerate.New(), service.Config{AccessTTL: cfg.AccessTTL, Resources: definitions, Native: native}, catalog)
	if err != nil {
		return App{}, err
	}
	ready, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(ready).Err(); err != nil {
		return App{}, err
	}
	assembly := App{service: svc, Handler: tokenhttp.New(svc, signer.PublicJWKS(), log)}
	assembly.Introspection, err = assembleIntrospection(pool, limiter, signer.PublicJWKS(), cfg, definitions, catalog, introspectionBudget)
	if err != nil {
		return App{}, err
	}
	assembly.Native, err = assembleNativeTokens(&assembly, login.Password, login.MFA, login.Email, deployment, log)
	if err != nil {
		return App{}, err
	}
	assembly.Deployment = settings.Deployment(cfg, definitions, assembly.Native != nil, assembly.Introspection != nil)
	return assembly, nil
}
