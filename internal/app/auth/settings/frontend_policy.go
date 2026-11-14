package settings

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func AssembleFrontendPolicy(ctx context.Context, repo *settingspostgres.Repository, cfg *config.Config, log *zap.Logger) (*settingshttp.FrontendPolicyHandler, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	mode := cfg.SettingsSource.Mode
	allowed, baseline := frontendBaseline(cfg)
	store := repo.FrontendPolicy()
	if err := store.Initialize(ctx, baseline); err != nil {
		return nil, err
	}
	load, invalidate := cachedPolicy(func(ctx context.Context) (domain.FrontendPolicy, error) {
		policy, err := store.Load(ctx)
		if err != nil {
			return policy, err
		}
		return policy, validateFrontend(policy, baseline, allowed)
	})
	if mode.Effective() == domain.SourceAPI {
		if _, err := load(ctx); err != nil {
			return nil, err
		}
		cfg.Browser.PolicySource = func(ctx context.Context) (middleware.OriginConfig, error) {
			value, err := load(ctx)
			return middleware.OriginConfig{AllowedOrigins: strings.Split(value.Origins, ","), CORSEnabled: value.CORSEnabled}, err
		}
		cfg.Account.URLSource = func(ctx context.Context) (string, error) {
			policy, err := load(ctx)
			return policy.VerificationURL, err
		}
		cfg.Password.URLSource = func(ctx context.Context) (string, error) {
			policy, err := load(ctx)
			return policy.ResetURL, err
		}
		cfg.Invitation.URLSource = func(ctx context.Context) (string, error) {
			policy, err := load(ctx)
			return policy.InvitationURL, err
		}
		cfg.EmailChange.URLSource = func(ctx context.Context) (string, string, string, error) {
			policy, err := load(ctx)
			return policy.EmailChangeURL, policy.EmailChangeReportURL, policy.EmailChangeRecoveryURL, err
		}
	}
	view := func(snapshot settingspostgres.PolicySnapshot[domain.FrontendPolicy]) settingshttp.FrontendPolicyView {
		return settingshttp.FrontendPolicyView{Version: snapshot.Version, Policy: settingshttp.FrontendPolicyDTO(snapshot.Policy), Source: mode.Metadata()}
	}
	return &settingshttp.FrontendPolicyHandler{
		Log: log,
		ReadPolicy: func(ctx context.Context, actor accessservice.Principal) (settingshttp.FrontendPolicyView, error) {
			snapshot, err := store.Read(ctx, actor)
			if mode == domain.SourceENV {
				snapshot.Policy = baseline
			}
			return view(snapshot), err
		},
		UpdatePolicy: func(ctx context.Context, actor accessservice.Principal, version int64, policy domain.FrontendPolicy) (settingshttp.FrontendPolicyView, error) {
			if (cfg.Invitation.Enabled && policy.InvitationURL == "") || (cfg.EmailChange.Enabled && policy.EmailChangeURL == "") {
				return settingshttp.FrontendPolicyView{}, domain.ErrInvalidFrontend
			}
			if err := validateFrontend(policy, baseline, allowed); err != nil {
				return settingshttp.FrontendPolicyView{}, err
			}
			snapshot, err := store.Update(ctx, actor, version, policy)
			if err == nil {
				invalidate()
			}
			return view(snapshot), err
		},
	}, nil
}

func RegistrationFrontendURL(cfg *config.Config) func(context.Context, pgx.Tx) (string, error) {
	if cfg.SettingsSource.Mode.Effective() != domain.SourceAPI {
		return nil
	}
	allowed, baseline := frontendBaseline(cfg)
	return func(ctx context.Context, tx pgx.Tx) (string, error) {
		policy, err := settingspostgres.LoadRegistrationFrontend(ctx, tx)
		if err != nil {
			return "", err
		}
		return policy.VerificationURL, validateFrontend(policy, baseline, allowed)
	}
}

func frontendBaseline(cfg *config.Config) ([]string, domain.FrontendPolicy) {
	allowed := cfg.Browser.AllowedOrigins
	return allowed, domain.FrontendPolicy{
		Origins: strings.Join(allowed, ","), CORSEnabled: cfg.Browser.CORSEnabled,
		VerificationURL: cfg.Account.URL, ResetURL: cfg.Password.ResetURL, InvitationURL: cfg.Invitation.URL,
		EmailChangeURL: cfg.EmailChange.ConfirmURL, EmailChangeReportURL: cfg.EmailChange.ReportURL, EmailChangeRecoveryURL: cfg.EmailChange.RecoveryURL,
	}
}

func validateFrontend(policy, baseline domain.FrontendPolicy, allowed []string) error {
	if policy == baseline {
		return nil
	}
	return policy.Validate(allowed)
}
