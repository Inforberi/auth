package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func assembleAccount(pool *pgxpool.Pool, redis *redis.Client, mail *mailer.Mailer, cfg accountservice.Config, emailChangeEnabled bool) (*accountservice.Service, *accountpostgres.Repository, error) {
	cipher, err := secretbox.New(cfg.EncryptionKey)
	if err != nil {
		return nil, nil, err
	}
	repo := accountpostgres.New(pool)
	if emailChangeEnabled {
		repo = accountpostgres.NewWithEmailChanges(pool)
	}
	service := accountservice.New(repo, accountredis.New(redis), cipher, mail, cfg)
	return service, repo, nil
}
