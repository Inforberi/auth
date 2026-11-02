package auth

import (
	"context"
	"errors"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func administrationAuthority(ctx context.Context, cfg *config.Config, deps realmDependencies) (*operatorpostgres.Repository, realmSecurity, error) {
	if err := cfg.ValidatePlatform(); err != nil {
		return nil, realmSecurity{}, err
	}
	if err := deps.validate(); err != nil {
		return nil, realmSecurity{}, err
	}
	// The installation chooses this identity; never reuse a caller-supplied project scope.
	scope, err := realmscope.New("platform", cfg.Platform.RealmID)
	if err != nil {
		return nil, realmSecurity{}, err
	}
	if deps.scope != scope {
		return nil, realmSecurity{}, errors.New("operator dependencies require the matching platform scope")
	}
	security := realmSecurity{scope: scope}
	operator, err := operatorpostgres.New(deps.pool, operatordomain.RealmID(cfg.Platform.RealmID))
	if err != nil {
		return nil, realmSecurity{}, err
	}
	if err := operator.CheckRuntime(ctx, cfg.InitialSetup.Enabled); err != nil {
		return nil, realmSecurity{}, err
	}
	return operator, security, nil
}
