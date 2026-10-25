package auth

import (
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type ProjectPasswordConfig struct {
	Session  sessionservice.Config
	Capacity passwordservice.CapacityConfig
	Timeout  time.Duration
}

type ProjectPasswordDependencies struct {
	Registry *projectruntime.Registry
	Reader   *projectpostgres.RuntimeCredentialReader
	Redis    *redis.Client
	Hash     *hasher.Bounded
}

func (c ProjectPasswordConfig) validate(deps ProjectPasswordDependencies) error {
	if deps.Registry == nil || deps.Reader == nil || deps.Redis == nil || deps.Hash == nil {
		return errors.New("incomplete project password dependencies")
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return errors.New("project password timeout must be positive and at most 30s")
	}
	if err := c.Capacity.Validate(); err != nil {
		return err
	}
	return c.Session.Validate()
}
