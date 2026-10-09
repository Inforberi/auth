package auth

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func assembleAccount(pool *pgxpool.Pool, redis *redis.Client, mail *mailer.Mailer, cfg accountservice.Config) (*accountservice.Service, *passwordpostgres.PasswordRepo, error) {
	cipher, err := secretbox.New(cfg.EncryptionKey)
	if err != nil {
		return nil, nil, err
	}
	repo := accountpostgres.New(pool)
	service := accountservice.New(repo, accountredis.New(redis), cipher, mail, cfg)
	passwordRepo := passwordpostgres.NewWithRegistration(pool, func(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, emailID accountdomain.AddressID, email string) error {
		prepared, err := service.Prepare(email)
		if err != nil {
			return err
		}
		return repo.QueueInTransaction(ctx, tx, user, emailID, prepared)
	})
	return service, passwordRepo, nil
}

func startDelivery(ctx context.Context, service interface {
	RunDelivery(context.Context, func(error))
}, log *zap.Logger,
) func() {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.RunDelivery(workerCtx, func(error) { log.Warn("email delivery processing failed") })
	}()
	return func() { cancel(); <-done }
}
