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

func AssembleCredentialLifetimePolicy(ctx context.Context, repo *settingspostgres.Repository, cfg *config.Config, log *zap.Logger) (*settingshttp.CredentialLifetimePolicyHandler, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	mode := cfg.SettingsSource.Mode
	baseline := credentialLifetimeBaseline(cfg)
	if err := baseline.Validate(); err != nil {
		return nil, err
	}
	store := repo.CredentialLifetimePolicy()
	if err := store.Initialize(ctx, baseline); err != nil {
		return nil, err
	}
	if mode.Effective() == domain.SourceAPI {
		policy, err := store.Load(ctx)
		if err != nil {
			return nil, err
		}
		if err := policy.Validate(); err != nil {
			return nil, err
		}
		load := func(ctx context.Context) (domain.CredentialLifetimePolicy, error) {
			policy, err := store.Load(ctx)
			if err != nil {
				return policy, err
			}
			return policy, policy.Validate()
		}
		bindCredentialLifetime(cfg, load)
	}
	view := func(snapshot settingspostgres.PolicySnapshot[domain.CredentialLifetimePolicy]) settingshttp.CredentialLifetimePolicyView {
		return settingshttp.CredentialLifetimePolicyView{Version: snapshot.Version, Policy: settingshttp.CredentialLifetimePolicyDTO(snapshot.Policy), Source: mode.Metadata()}
	}
	return &settingshttp.CredentialLifetimePolicyHandler{
		Log: log,
		ReadPolicy: func(ctx context.Context, actor accessservice.Principal) (settingshttp.CredentialLifetimePolicyView, error) {
			snapshot, err := store.Read(ctx, actor)
			if mode == domain.SourceENV {
				snapshot.Policy = baseline
			}
			return view(snapshot), err
		},
		UpdatePolicy: func(ctx context.Context, actor accessservice.Principal, version int64, policy domain.CredentialLifetimePolicy) (settingshttp.CredentialLifetimePolicyView, error) {
			if err := policy.Validate(); err != nil {
				return settingshttp.CredentialLifetimePolicyView{}, err
			}
			snapshot, err := store.Update(ctx, actor, version, policy)
			return view(snapshot), err
		},
	}, nil
}

func credentialLifetimeBaseline(cfg *config.Config) domain.CredentialLifetimePolicy {
	return domain.CredentialLifetimePolicy{
		MFAChallengeSeconds:             int64(cfg.MFA.ChallengeTTL / time.Second),
		FreshAuthSeconds:                int64(cfg.Session.FreshAuthTTL / time.Second),
		EmailBindingSeconds:             int64(cfg.EmailBinding.TTL / time.Second),
		InvitationSeconds:               int64(cfg.Invitation.TTL / time.Second),
		InvitationCooldownSeconds:       int64(cfg.Invitation.ReissueCooldown / time.Second),
		TemporaryReissueCooldownSeconds: int64(cfg.TemporaryPassword.ReissueCooldown / time.Second),
		TemporaryPasswordSeconds:        int64(cfg.TemporaryPassword.TTL / time.Second),
		TemporarySetupSeconds:           int64(cfg.TemporaryPassword.SetupTTL / time.Second),
		EmailChangeSeconds:              int64(cfg.EmailChange.TTL / time.Second),
		EmailChangeRecoverySeconds:      int64(cfg.EmailChange.RecoveryTTL / time.Second),
		EmailChangeProtectionSeconds:    int64(cfg.EmailChange.ProtectionTTL / time.Second),
	}
}

func bindCredentialLifetime(cfg *config.Config, load func(context.Context) (domain.CredentialLifetimePolicy, error)) {
	cfg.Session.FreshAuthSource = func(ctx context.Context) (time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.FreshAuthSeconds) * time.Second, err
	}
	cfg.MFA.ChallengeTTLSource = func(ctx context.Context) (time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.MFAChallengeSeconds) * time.Second, err
	}
	cfg.EmailBinding.TTLSource = func(ctx context.Context) (time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.EmailBindingSeconds) * time.Second, err
	}
	cfg.Invitation.TTLSource = func(ctx context.Context) (time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.InvitationSeconds) * time.Second, err
	}
	cfg.Invitation.ReissuePolicySource = func(ctx context.Context) (time.Duration, time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.InvitationSeconds) * time.Second, time.Duration(policy.InvitationCooldownSeconds) * time.Second, err
	}
	cfg.TemporaryPassword.ReissuePolicySource = func(ctx context.Context) (time.Duration, time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.TemporaryPasswordSeconds) * time.Second, time.Duration(policy.TemporaryReissueCooldownSeconds) * time.Second, err
	}
	cfg.TemporaryPassword.TTLSource = func(ctx context.Context) (time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.TemporaryPasswordSeconds) * time.Second, err
	}
	cfg.TemporaryPassword.SetupTTLSource = func(ctx context.Context) (time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.TemporarySetupSeconds) * time.Second, err
	}
	cfg.EmailChange.LifetimeSource = func(ctx context.Context) (time.Duration, time.Duration, time.Duration, error) {
		policy, err := load(ctx)
		return time.Duration(policy.EmailChangeSeconds) * time.Second,
			time.Duration(policy.EmailChangeRecoverySeconds) * time.Second,
			time.Duration(policy.EmailChangeProtectionSeconds) * time.Second, err
	}
}
