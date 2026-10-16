package auth

import (
	"context"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	telegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	telegramclient "github.com/Inforberi/financial-intelligence/internal/integrations/telegram"
)

func assembleTelegram(ctx context.Context, cfg *config.Config, accounts *accountpostgres.Repository, rdb *redis.Client, sessions *sessionservice.Login, policy *settingsservice.Service, log *zap.Logger) (*telegramhttp.Handler, func(), error) {
	if !cfg.Telegram.Enabled {
		return nil, nil, nil
	}
	client := telegramclient.New(ctx, cfg.Telegram)
	service, err := assembleOIDC(cfg, cfg.Telegram.FlowConfig(), client, accounts, rdb, sessions, policy)
	if err != nil {
		return nil, nil, err
	}
	return telegramhttp.New(service, log), client.Close, nil
}
