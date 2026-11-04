package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

// These dependencies are borrowed. Realm cleanup never closes their process owner.
type Dependencies struct {
	Pool   *pgxpool.Pool
	Redis  *redis.Client
	Logger *zap.Logger
	Hash   *hasher.Bounded
	Scope  realmscope.Scope
}

func (d Dependencies) validate() error {
	if d.Pool == nil || d.Redis == nil || d.Logger == nil || d.Hash == nil || !d.Scope.Valid() {
		return errors.New("auth realm requires pool, Redis, logger, shared hasher and explicit scope")
	}
	return nil
}

type Runtime struct {
	Access             *accessapp.App
	Provisioning       *accountprovisioning.ProvisionService
	TemporaryPasswords *passwordprovisioning.TemporaryPasswordService
	Handler            http.Handler
	drainHTTP          func()
	retention          retentionWorker
	workers            []deliveryWorker
	resources          *Resources
}

func Assemble(ctx context.Context, cfg *config.Config, deps Dependencies) (*Runtime, error) {
	if cfg.Platform.Enabled {
		return assembleOperator(ctx, cfg, deps, mailer.New(cfg.MailSender))
	}
	return assembleRealm(ctx, cfg, deps)
}

func (r *Runtime) Close() { r.resources.Close() }
