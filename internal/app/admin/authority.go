package admin

import (
	"context"
	"errors"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	authapp "github.com/Inforberi/financial-intelligence/internal/app/auth"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func administrationAuthority(ctx context.Context, cfg *config.Config, deps authapp.Dependencies) (*operatorpostgres.Repository, realmscope.Scope, error) {
	if err := cfg.ValidatePlatform(); err != nil {
		return nil, realmscope.Scope{}, err
	}
	if err := deps.Validate(); err != nil {
		return nil, realmscope.Scope{}, err
	}
	// The installation chooses this identity; never reuse a caller-supplied project scope.
	scope, err := realmscope.New("platform", cfg.Platform.RealmID)
	if err != nil {
		return nil, realmscope.Scope{}, err
	}
	if deps.Scope != scope {
		return nil, realmscope.Scope{}, errors.New("operator dependencies require the matching platform scope")
	}

	operator, err := operatorpostgres.New(deps.Pool, operatordomain.RealmID(cfg.Platform.RealmID))
	if err != nil {
		return nil, realmscope.Scope{}, err
	}
	if err := operator.CheckRuntime(ctx, cfg.InitialSetup.Enabled); err != nil {
		return nil, realmscope.Scope{}, err
	}
	return operator, scope, nil
}

func operatorReadyCheck(deps authapp.Dependencies, runtime *projectapp.Runtime) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := deps.Pool.Ping(ctx); err != nil {
			return err
		}
		if runtime != nil {
			if err := runtime.Reader.CheckRuntime(ctx); err != nil {
				return err
			}
		}
		return deps.Redis.Ping(ctx).Err()
	}
}
