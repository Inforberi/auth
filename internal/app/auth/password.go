package auth

import (
	"context"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type passwordApp struct {
	service    *passwordservice.PasswordService
	recovery   *passwordservice.RecoveryService
	limits     *passwordredis.RedisRepo
	cipher     *secretbox.Cipher
	loginLimit *passwordservice.LoginLimit
}

func (s realmSecurity) assemblePassword(repo *passwordpostgres.PasswordRepo, rdb *redis.Client, sessions *sessionservice.Login, hash *hasher.Bounded, policy *settingsservice.Service, mail passwordservice.RecoveryMailer, cfg *config.Config) (*passwordApp, error) {
	cipher, err := s.cipher(cfg.Account.EncryptionKey, "password-reset:v1")
	if err != nil {
		return nil, err
	}
	limits, err := passwordredis.NewScoped(rdb, s.scope)
	if err != nil {
		return nil, err
	}
	loginLimit := passwordservice.NewLoginLimit(limits, cipher, cfg.Capacity)
	service := passwordservice.New(repo, sessions, hash, loginLimit).WithPublicPolicy(func(ctx context.Context, registration bool) error {
		return policy.CheckPublic(ctx, "password", registration)
	})
	return &passwordApp{
		service: service, limits: limits, cipher: cipher, loginLimit: loginLimit,
		recovery: passwordservice.NewRecovery(repo, cipher, limits, mail, hash, cfg.Password),
	}, nil
}
