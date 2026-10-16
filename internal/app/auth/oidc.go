package auth

import (
	"context"

	"github.com/redis/go-redis/v9"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	oidcredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/repository/redis"
	oidcservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	oidcclient "github.com/Inforberi/financial-intelligence/internal/integrations/oidc"
)

func assembleOIDC(cfg *config.Config, flow oidcservice.Config, client *oidcclient.Client, accounts *accountpostgres.Repository, rdb *redis.Client, sessions *sessionservice.Login, policy *settingsservice.Service) (*oidcservice.Service, error) {
	method := settingsdomain.PrimaryMethod("oidc", flow.Issuer)
	cipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, method+"-login:v1")
	if err != nil {
		client.Close()
		return nil, err
	}
	flow.CheckPolicy = func(ctx context.Context) error { return policy.CheckPublic(ctx, method, false) }
	return oidcservice.New(flow, oidcredis.New(rdb, cipher, "auth:"+method), client,
		accountservice.NewIdentityResolution(accounts), sessions, tokengenerate.New(),
		accountservice.NewIdentityManagement(accounts, cfg.Session.FreshAuthTTL)), nil
}
