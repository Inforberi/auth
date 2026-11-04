package auth

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
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

func (d Dependencies) Validate() error {
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
	retention          RetentionWorker
	workers            []DeliveryWorker
	resources          *Resources
}

func (r *Runtime) Close() { r.resources.Close() }

// NewRuntime binds a completed graph to its owned lifecycle resources.
func NewRuntime(handler http.Handler, retention RetentionWorker, workers []DeliveryWorker, resources *Resources, drain func()) *Runtime {
	return &Runtime{Handler: handler, retention: retention, workers: workers, resources: resources, drainHTTP: drain}
}
