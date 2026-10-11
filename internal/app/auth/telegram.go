package auth

import (
	"context"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	telegramredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/repository/redis"
	telegramservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	telegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	telegramclient "github.com/Inforberi/financial-intelligence/internal/integrations/telegram"
)

func assembleTelegram(ctx context.Context, cfg *config.Config, accounts *accountpostgres.Repository, rdb *redis.Client, sessions *sessionservice.SessionService, log *zap.Logger) (*telegramhttp.Handler, func(), error) {
	if !cfg.Telegram.Enabled {
		return nil, nil, nil
	}
	cipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, "telegram-login:v1")
	if err != nil {
		return nil, nil, err
	}
	client := telegramclient.New(ctx, cfg.Telegram)
	service := telegramservice.New(cfg.Telegram, telegramredis.New(rdb, cipher), client,
		accountservice.NewIdentityResolution(accounts), sessions, tokengenerate.New())
	return telegramhttp.New(service, log), client.Close, nil
}
