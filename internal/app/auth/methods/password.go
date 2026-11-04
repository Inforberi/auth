package methods

import (
	"context"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type Password struct {
	Service    *passwordservice.PasswordService
	Recovery   *passwordrecovery.RecoveryService
	limits     *passwordredis.RedisRepo
	cipher     *secretbox.Cipher
	loginLimit *passwordservice.LoginLimit
}

func AssemblePassword(scope realmscope.Scope, repo *passwordpostgres.PasswordRepo, rdb *redis.Client, sessions *sessionservice.Login, hash *hasher.Bounded, policy *settingsservice.Service, mail passwordrecovery.RecoveryMailer, cfg *config.Config) (*Password, error) {
	cipher, err := secretbox.ForScope(scope, cfg.Account.EncryptionKey, "password-reset:v1")
	if err != nil {
		return nil, err
	}
	limits, err := passwordredis.NewScoped(rdb, scope)
	if err != nil {
		return nil, err
	}
	loginLimit := passwordservice.NewLoginLimit(limits, cipher, cfg.Capacity)
	service := passwordservice.New(repo, sessions, hash, loginLimit).WithPublicPolicy(func(ctx context.Context, registration bool) error {
		return policy.CheckPublic(ctx, "password", registration)
	})
	return &Password{
		Service: service, limits: limits, cipher: cipher, loginLimit: loginLimit,
		Recovery: passwordrecovery.NewRecovery(repo, cipher, limits, mail, hash, cfg.Password),
	}, nil
}
