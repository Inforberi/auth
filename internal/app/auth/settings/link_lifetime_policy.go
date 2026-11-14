package settings

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func AssembleLinkLifetimePolicy(ctx context.Context, repo *settingspostgres.Repository, cfg *config.Config, log *zap.Logger) (*settingshttp.LinkLifetimePolicyHandler, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	mode := cfg.SettingsSource.Mode
	baseline := domain.LinkLifetimePolicy{VerificationSeconds: int64(cfg.Account.TTL / time.Second), ResetSeconds: int64(cfg.Password.ResetTokenTTL / time.Second)}
	resendSeconds := int64(cfg.Account.ResendInterval / time.Second)
	if err := baseline.Validate(resendSeconds); err != nil {
		return nil, err
	}
	store := repo.LinkLifetimePolicy()
	if err := store.Initialize(ctx, baseline); err != nil {
		return nil, err
	}
	if mode.Effective() == domain.SourceAPI {
		policy, err := store.Load(ctx)
		if err != nil {
			return nil, err
		}
		if err := policy.Validate(resendSeconds); err != nil {
			return nil, err
		}
		load := func(ctx context.Context) (domain.LinkLifetimePolicy, error) {
			policy, err := store.Load(ctx)
			if err != nil {
				return policy, err
			}
			return policy, policy.Validate(resendSeconds)
		}
		cfg.Account.TTLSource = func(ctx context.Context) (time.Duration, error) {
			policy, err := load(ctx)
			return time.Duration(policy.VerificationSeconds) * time.Second, err
		}
		cfg.Password.TTLSource = func(ctx context.Context) (time.Duration, error) {
			policy, err := load(ctx)
			return time.Duration(policy.ResetSeconds) * time.Second, err
		}
	}
	view := func(snapshot settingspostgres.PolicySnapshot[domain.LinkLifetimePolicy]) settingshttp.LinkLifetimePolicyView {
		return settingshttp.LinkLifetimePolicyView{Version: snapshot.Version, Policy: settingshttp.LinkLifetimePolicyDTO(snapshot.Policy), Source: mode.Metadata()}
	}
	return &settingshttp.LinkLifetimePolicyHandler{
		Log: log,
		ReadPolicy: func(ctx context.Context, actor accessservice.Principal) (settingshttp.LinkLifetimePolicyView, error) {
			snapshot, err := store.Read(ctx, actor)
			if mode == domain.SourceENV {
				snapshot.Policy = baseline
			}
			return view(snapshot), err
		},
		UpdatePolicy: func(ctx context.Context, actor accessservice.Principal, version int64, policy domain.LinkLifetimePolicy) (settingshttp.LinkLifetimePolicyView, error) {
			if err := policy.Validate(resendSeconds); err != nil {
				return settingshttp.LinkLifetimePolicyView{}, err
			}
			snapshot, err := store.Update(ctx, actor, version, policy)
			return view(snapshot), err
		},
	}, nil
}

func RegistrationLinkTTL(cfg *config.Config) func(context.Context, pgx.Tx) (time.Duration, error) {
	if cfg.SettingsSource.Mode.Effective() != domain.SourceAPI {
		return nil
	}
	resendSeconds := int64(cfg.Account.ResendInterval / time.Second)
	return func(ctx context.Context, tx pgx.Tx) (time.Duration, error) {
		policy, err := settingspostgres.LoadRegistrationLinkLifetime(ctx, tx)
		if err != nil {
			return 0, err
		}
		if err := policy.Validate(resendSeconds); err != nil {
			return 0, err
		}
		return time.Duration(policy.VerificationSeconds) * time.Second, nil
	}
}
