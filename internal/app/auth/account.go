package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountemailhttp "github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accountsetup "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/service"
	accountsetuphttp "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
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

func (s realmSecurity) assembleSetup(repo accountsetup.SetupRepository, rdb *redis.Client, mail accountservice.Mailer, hash *hasher.Bounded, cfg *config.Config, log *zap.Logger) (*accountsetuphttp.SetupHandler, error) {
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
	svc, err := accountsetup.NewSetup(repo, limits, cipher, factorCipher, mail, hash, totp.Authenticator{}, cfg.InitialSetup, cfg.MFA.Issuer)
	if err != nil {
		return nil, err
	}
	return accountsetuphttp.NewSetup(svc, log), nil
}
