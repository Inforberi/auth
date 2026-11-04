package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

type accountApp struct {
	verification *accountemail.Verification
	repository   *accountpostgres.Repository
	limits       accountservice.Limiter
	cipher       accountservice.Cipher
}

func (s realmSecurity) assembleAccount(pool *pgxpool.Pool, redis *redis.Client, mail accountservice.Mailer, cfg accountservice.Config, delivery accountpostgres.DeliveryConfig) (*accountApp, error) {
	cipher, err := s.cipher(cfg.EncryptionKey, "email-verification:v1")
	if err != nil {
		return nil, err
	}
	repo := accountpostgres.NewWithDelivery(pool, delivery)
	limits, err := accountredis.NewScoped(redis, s.scope)
	if err != nil {
		return nil, err
	}
	service := accountemail.NewVerification(repo, limits, cipher, mail, cfg)
	return &accountApp{verification: service, repository: repo, limits: limits, cipher: cipher}, nil
}

func (s realmSecurity) assembleEmailBinding(repo *accountpostgres.Repository, rdb *redis.Client, cfg *config.Config, log *zap.Logger) (*accountemailhttp.EmailBindingHandler, error) {
	if !cfg.EmailBinding.Enabled {
		return nil, nil
	}
	cipher, err := s.cipher(cfg.Account.EncryptionKey, "email-verification:v1")
	if err != nil {
		return nil, err
	}
	limits, err := accountredis.NewScoped(rdb, s.scope)
	if err != nil {
		return nil, err
	}
	svc := accountemail.NewEmailBinding(repo, limits, cipher, cfg.EmailBinding)
	return accountemailhttp.NewEmailBinding(svc, log), nil
}
