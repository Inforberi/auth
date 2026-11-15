package profile

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	authsettings "github.com/Inforberi/financial-intelligence/internal/app/auth/settings"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func bindProjectLoginBudgets(cfg runtimeprofile.ProjectProfileConfig, key projectruntime.Key, deps runtimeprofile.ProjectProfileDependencies) runtimeprofile.ProjectProfileConfig {
	if cfg.Password == nil {
		return cfg
	}
	password := *cfg.Password
	baseline := cfg.LoginBudgetBaseline
	if baseline.Validate(baseline) != nil {
		return cfg
	}
	load, _ := authsettings.CachedPolicy(func(ctx context.Context) (settings.LoginBudgetPolicy, error) {
		var result settings.LoginBudgetPolicy
		err := deps.Registry.UsePool(ctx, key, func(ctx context.Context, pool *pgxpool.Pool) error {
			var err error
			result, err = settingspg.New(pool).ProjectLoginBudget(ctx, baseline)
			return err
		})
		return result, err
	})
	password.Capacity.LoginBudgetSource = load
	cfg.Password = &password
	if cfg.Verification != nil {
		verification := *cfg.Verification
		verification.RegistrationBudgetSource = func(ctx context.Context) (int, int, error) {
			policy, err := load(ctx)
			return policy.RegistrationIPPerMinute, policy.RegistrationGlobalPerMinute, err
		}
		cfg.Verification = &verification
	}
	if cfg.Recovery != nil {
		recovery := *cfg.Recovery
		recovery.ResetBudgetSource = func(ctx context.Context) (int, error) {
			policy, err := load(ctx)
			return policy.ResetGlobalPerMinute, err
		}
		cfg.Recovery = &recovery
	}
	return cfg
}
