package methods

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/transport/http"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type Temporary struct {
	Service *passwordprovisioning.TemporaryPasswordService
	Handler *passwordprovisioninghttp.TemporaryPasswordHandler
	Admin   *passwordprovisioninghttp.TemporaryAdminHandler
}

func (p *Password) AssembleTemporary(pool *pgxpool.Pool, accounts *accountpostgres.Repository, hash *hasher.Bounded, cfg *config.Config, log *zap.Logger) Temporary {
	if !cfg.TemporaryPassword.Enabled {
		return Temporary{}
	}
	repo := passwordpostgres.NewTemporaryPassword(pool, accounts.ProvisionInTransaction)
	svc := passwordprovisioning.NewTemporaryPassword(repo, hash, p.limits, p.cipher.Digest, p.loginLimit, cfg.TemporaryPassword)
	return Temporary{Service: svc, Handler: passwordprovisioninghttp.NewTemporaryPassword(svc, log), Admin: passwordprovisioninghttp.NewTemporaryAdmin(svc, log)}
}

func (p *Password) AssembleActivation(accounts *accountpostgres.Repository, hash *hasher.Bounded, cfg *config.Config, log *zap.Logger) *passwordprovisioninghttp.ActivationHandler {
	if !cfg.Invitation.Enabled {
		return nil
	}
	svc := passwordprovisioning.NewActivation(accounts, hash, p.limits, p.cipher.Digest, cfg.Invitation)
	return passwordprovisioninghttp.NewActivation(svc, log)
}

func (p *Password) Reauthentication(credentials *passwordpostgres.PasswordRepo, sessions *sessionpostgres.Repository, hash *hasher.Bounded, tokens *tokengenerate.TokenManager, ttl time.Duration, source func(context.Context) (time.Duration, error), log *zap.Logger) *passwordhttp.ReauthenticationHandler {
	svc := passwordservice.NewReauthentication(credentials, sessions, hash, p.loginLimit, tokens, ttl).WithFreshAuthSource(source)
	return passwordhttp.NewReauthentication(svc, log)
}
