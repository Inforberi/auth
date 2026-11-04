package methods

import (
	"context"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	telegramhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsproviders "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	telegramclient "github.com/Inforberi/financial-intelligence/internal/integrations/telegram"
)

func AssembleTelegram(ctx context.Context, scope realmscope.Scope, cfg *config.Config, accounts *accountpostgres.Repository, rdb *redis.Client, sessions *sessionservice.Login, policy *settingsservice.Service, providers *settingsproviders.Providers, log *zap.Logger) (*telegramhttp.Handler, func(), error) {
	if !cfg.Telegram.Enabled {
		return nil, nil, nil
	}
	client := telegramclient.New(ctx, cfg.Telegram)
	service, err := assembleOIDC(scope, cfg, cfg.Telegram.FlowConfig(), client, accounts, rdb, sessions, policy, providers)
	if err != nil {
		return nil, nil, err
	}
	return telegramhttp.New(service, log), client.Close, nil
}
