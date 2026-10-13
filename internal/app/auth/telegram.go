package auth

import (
	"context"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	oidcredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/repository/redis"
	oidcservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	telegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	telegramclient "github.com/Inforberi/financial-intelligence/internal/integrations/telegram"
)

func assembleTelegram(ctx context.Context, cfg *config.Config, accounts *accountpostgres.Repository, rdb *redis.Client, sessions *sessionservice.Login, log *zap.Logger) (*telegramhttp.Handler, func(), error) {
	if !cfg.Telegram.Enabled {
		return nil, nil, nil
	}
	cipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, "telegram-login:v1")
	if err != nil {
		return nil, nil, err
	}
	client := telegramclient.New(ctx, cfg.Telegram)
	service := oidcservice.New(cfg.Telegram.FlowConfig(), oidcredis.New(rdb, cipher, "auth:telegram"), client,
		accountservice.NewIdentityResolution(accounts), sessions, tokengenerate.New(),
		accountservice.NewIdentityManagement(accounts, cfg.Session.FreshAuthTTL))
	return telegramhttp.New(service, log), client.Close, nil
}
