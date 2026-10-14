package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func assembleAccount(pool *pgxpool.Pool, redis *redis.Client, mail *mailer.Mailer, cfg accountservice.Config, delivery accountpostgres.DeliveryConfig) (*accountservice.Service, *accountpostgres.Repository, error) {
	cipher, err := secretbox.New(cfg.EncryptionKey)
	if err != nil {
		return nil, nil, err
	}
	repo := accountpostgres.NewWithDelivery(pool, delivery)
	service := accountservice.New(repo, accountredis.New(redis), cipher, mail, cfg)
	return service, repo, nil
}

func assembleEmailBinding(repo *accountpostgres.Repository, rdb *redis.Client, cfg *config.Config, log *zap.Logger) (*accounthttp.EmailBindingHandler, error) {
	if !cfg.EmailBinding.Enabled {
		return nil, nil
	}
	cipher, err := secretbox.New(cfg.Account.EncryptionKey)
	if err != nil {
		return nil, err
	}
	svc := accountservice.NewEmailBinding(repo, accountredis.New(rdb), cipher, cfg.EmailBinding)
	return accounthttp.NewEmailBinding(svc, log), nil
}
