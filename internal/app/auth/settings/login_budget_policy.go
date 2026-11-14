package settings

import (
	"context"
	"time"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func AssembleLoginBudgetPolicy(ctx context.Context, repo *settingspostgres.Repository, cfg *config.Config, log *zap.Logger) (*settingshttp.LoginBudgetPolicyHandler, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	mode := cfg.SettingsSource.Mode
	baseline := domain.LoginBudgetPolicy{IPPerMinute: cfg.Capacity.LoginIPLimit, IdentityPerMinute: cfg.Capacity.LoginEmailLimit, GlobalPerMinute: cfg.Capacity.LoginGlobalLimit, RegistrationIPPerMinute: cfg.Account.RegistrationIPLimit, RegistrationGlobalPerMinute: cfg.Account.RegistrationGlobalLimit, ResetGlobalPerMinute: cfg.Password.ResetGlobalLimit}
	if err := baseline.Validate(baseline); err != nil {
		return nil, err
	}
	store := repo.LoginBudgetPolicy()
	if err := store.Initialize(ctx, baseline); err != nil {
		return nil, err
	}
	load, invalidate := cachedPolicy(store.Load)
	if mode.Effective() == domain.SourceAPI {
		policy, err := store.Load(ctx)
		if err != nil {
			return nil, err
		}
		if err := policy.Validate(baseline); err != nil {
			return nil, err
		}
		cfg.Capacity.LoginBudgetSource = func(ctx context.Context) (domain.LoginBudgetPolicy, error) {
			policy, err := load(ctx)
			if err != nil {
				return policy, err
			}
			return policy, policy.Validate(baseline)
		}
		cfg.Account.RegistrationBudgetSource = func(ctx context.Context) (int, int, error) {
			policy, err := cfg.Capacity.LoginBudgetSource(ctx)
			return policy.RegistrationIPPerMinute, policy.RegistrationGlobalPerMinute, err
		}
		cfg.Password.ResetBudgetSource = func(ctx context.Context) (int, error) {
			policy, err := cfg.Capacity.LoginBudgetSource(ctx)
			return policy.ResetGlobalPerMinute, err
		}
	}
	view := func(snapshot settingspostgres.PolicySnapshot[domain.LoginBudgetPolicy]) settingshttp.LoginBudgetPolicyView {
		return settingshttp.LoginBudgetPolicyView{Version: snapshot.Version, Policy: settingshttp.LoginBudgetPolicyDTO(snapshot.Policy), Source: mode.Metadata()}
	}
	return &settingshttp.LoginBudgetPolicyHandler{
		Log: log,
		ReadPolicy: func(ctx context.Context, actor accessservice.Principal) (settingshttp.LoginBudgetPolicyView, error) {
			snapshot, err := store.Read(ctx, actor)
			if mode == domain.SourceENV {
				snapshot.Policy = baseline
			}
			return view(snapshot), err
		},
		UpdatePolicy: func(ctx context.Context, actor accessservice.Principal, version int64, policy domain.LoginBudgetPolicy) (settingshttp.LoginBudgetPolicyView, error) {
			if err := policy.Validate(baseline); err != nil {
				return settingshttp.LoginBudgetPolicyView{}, err
			}
			snapshot, err := store.Update(ctx, actor, version, policy)
			if err == nil {
				invalidate()
			}
			return view(snapshot), err
		},
	}, nil
}
