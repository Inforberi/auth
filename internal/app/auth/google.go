package auth

import (
	"context"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	googlehttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	googleclient "github.com/Inforberi/financial-intelligence/internal/integrations/google"
)

func (s realmSecurity) assembleGoogle(ctx context.Context, cfg *config.Config, accounts *accountpostgres.Repository, rdb *redis.Client, sessions *sessionservice.Login, policy *settingsservice.Service, providers *settingsservice.Providers, log *zap.Logger) (*googlehttp.Handler, func(), error) {
	if !cfg.Google.Enabled {
		return nil, nil, nil
	}
	client := googleclient.New(ctx, cfg.Google)
	service, err := s.assembleOIDC(cfg, cfg.Google.FlowConfig(), client, accounts, rdb, sessions, policy, providers)
	if err != nil {
		return nil, nil, err
	}
	return googlehttp.New(service, log), client.Close, nil
}
