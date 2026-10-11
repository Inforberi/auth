package auth

import (
	"context"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	googlehttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/transport/http"
	oidcredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/repository/redis"
	oidcservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	googleclient "github.com/Inforberi/financial-intelligence/internal/integrations/google"
)

func assembleGoogle(ctx context.Context, cfg *config.Config, accounts *accountpostgres.Repository, rdb *redis.Client, sessions *sessionservice.SessionService, log *zap.Logger) (*googlehttp.Handler, func(), error) {
	if !cfg.Google.Enabled {
		return nil, nil, nil
	}
	cipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, "google-login:v1")
	if err != nil {
		return nil, nil, err
	}
	client := googleclient.New(ctx, cfg.Google)
	service := oidcservice.New(cfg.Google.FlowConfig(), oidcredis.New(rdb, cipher, "auth:google"), client,
		accountservice.NewIdentityResolution(accounts), sessions, tokengenerate.New(),
		accountservice.NewIdentityManagement(accounts, cfg.Session.FreshAuthTTL))
	return googlehttp.New(service, log), client.Close, nil
}
