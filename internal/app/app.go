package app

import (
	"context"
	"errors"

	"github.com/Inforberi/financial-intelligence/internal/app/auth"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func New(ctx context.Context, cfg *config.Config) (_ *App, err error) {
	if err := cfg.ValidatePlatform(); err != nil {
		return nil, err
	}
	owned := &auth.Resources{}
	defer func() {
		if err != nil {
			owned.Close()
		}
	}()
	pool, rdb, log, err := openResources(ctx, cfg, owned)
	if err != nil {
		return nil, err
	}
	if cfg.Capacity.HashConcurrency < 1 {
		return nil, errors.New("password hash concurrency must be positive")
	}
	deps := auth.Dependencies{
		Pool: pool, Redis: rdb, Logger: log,
		Scope: realmscope.Legacy(),
		Hash:  hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), cfg.Capacity.HashConcurrency),
	}
	if cfg.Platform.Enabled {
		deps.Scope, err = realmscope.New("platform", cfg.Platform.RealmID)
		if err != nil {
			return nil, err
		}
	}
	assembled, err := auth.Assemble(ctx, cfg, deps)
	if err != nil {
		return nil, err
	}
	owned.Add(assembled.Close)
	return newApplication(assembled, owned, log, cfg.Server), nil
}
