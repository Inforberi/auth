package setup

import (
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accountsetup "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/setup/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func Assemble(scope realmscope.Scope, repo accountsetup.SetupRepository, rdb *redis.Client, mail accountservice.Mailer, hash *hasher.Bounded, cfg *config.Config, log *zap.Logger) (*accountsetuphttp.SetupHandler, error) {
	if !cfg.InitialSetup.Enabled {
		return nil, nil
	}
	cipher, err := secretbox.ForScope(scope, cfg.Account.EncryptionKey, "initial-setup:v1")
	if err != nil {
		return nil, err
	}
	factorCipher, err := secretbox.ForScope(scope, cfg.Account.EncryptionKey, "mfa:v1")
	if err != nil {
		return nil, err
	}
	limits, err := accountredis.NewScoped(rdb, scope)
	if err != nil {
		return nil, err
	}
	svc, err := accountsetup.NewSetup(repo, limits, cipher, factorCipher, mail, hash, totp.Authenticator{}, cfg.InitialSetup, cfg.MFA.Issuer)
	if err != nil {
		return nil, err
	}
	return accountsetuphttp.NewSetup(svc, log), nil
}
