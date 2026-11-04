package account

import (
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type App struct {
	Verification *accountemail.Verification
	repository   *accountpostgres.Repository
	limits       accountservice.Limiter
	cipher       accountservice.Cipher
}

func Assemble(scope realmscope.Scope, repo *accountpostgres.Repository, redis *redis.Client, mail accountservice.Mailer, cfg accountservice.Config) (*App, error) {
	cipher, err := secretbox.ForScope(scope, cfg.EncryptionKey, "email-verification:v1")
	if err != nil {
		return nil, err
	}
	limits, err := accountredis.NewScoped(redis, scope)
	if err != nil {
		return nil, err
	}
	service := accountemail.NewVerification(repo, limits, cipher, mail, cfg)
	return &App{Verification: service, repository: repo, limits: limits, cipher: cipher}, nil
}

func AssembleEmailBinding(scope realmscope.Scope, repo *accountpostgres.Repository, rdb *redis.Client, cfg *config.Config, log *zap.Logger) (*accountemailhttp.EmailBindingHandler, error) {
	if !cfg.EmailBinding.Enabled {
		return nil, nil
	}
	cipher, err := secretbox.ForScope(scope, cfg.Account.EncryptionKey, "email-verification:v1")
	if err != nil {
		return nil, err
	}
	limits, err := accountredis.NewScoped(rdb, scope)
	if err != nil {
		return nil, err
	}
	svc := accountemail.NewEmailBinding(repo, limits, cipher, cfg.EmailBinding)
	return accountemailhttp.NewEmailBinding(svc, log), nil
}
