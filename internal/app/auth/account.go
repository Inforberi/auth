package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (s realmSecurity) assembleAccount(pool *pgxpool.Pool, redis *redis.Client, mail *mailer.Mailer, cfg accountservice.Config, delivery accountpostgres.DeliveryConfig) (*accountservice.Service, *accountpostgres.Repository, error) {
	cipher, err := s.cipher(cfg.EncryptionKey, "email-verification:v1")
	if err != nil {
		return nil, nil, err
	}
	repo := accountpostgres.NewWithDelivery(pool, delivery)
	limits, err := accountredis.NewScoped(redis, s.scope)
	if err != nil {
		return nil, nil, err
	}
	service := accountservice.New(repo, limits, cipher, mail, cfg)
	return service, repo, nil
}

func (s realmSecurity) assembleEmailBinding(repo *accountpostgres.Repository, rdb *redis.Client, cfg *config.Config, log *zap.Logger) (*accounthttp.EmailBindingHandler, error) {
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
	svc := accountservice.NewEmailBinding(repo, limits, cipher, cfg.EmailBinding)
	return accounthttp.NewEmailBinding(svc, log), nil
}

func (s realmSecurity) assembleSetup(repo *accountpostgres.Repository, rdb *redis.Client, mail *mailer.Mailer, hash *hasher.Bounded, cfg *config.Config, log *zap.Logger) (*accounthttp.SetupHandler, error) {
	if !cfg.InitialSetup.Enabled {
		return nil, nil
	}
	cipher, err := s.cipher(cfg.Account.EncryptionKey, "initial-setup:v1")
	if err != nil {
		return nil, err
	}
	factorCipher, err := s.cipher(cfg.Account.EncryptionKey, "mfa:v1")
	if err != nil {
		return nil, err
	}
	limits, err := accountredis.NewScoped(rdb, s.scope)
	if err != nil {
		return nil, err
	}
	svc, err := accountservice.NewSetup(repo, limits, cipher, factorCipher, mail, hash, mfatotp.Authenticator{}, cfg.InitialSetup, cfg.MFA.Issuer)
	if err != nil {
		return nil, err
	}
	return accounthttp.NewSetup(svc, log), nil
}
