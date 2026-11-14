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

func AssembleOperationBudgetsPolicy(ctx context.Context, repo *settingspostgres.Repository, cfg *config.Config, log *zap.Logger) (*settingshttp.OperationBudgetsPolicyHandler, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	mode := cfg.SettingsSource.Mode
	baseline := domain.OperationBudgetsPolicy{
		GoogleIP:         cfg.Google.IPLimit,
		GoogleGlobal:     cfg.Google.GlobalLimit,
		TelegramIP:       cfg.Telegram.IPLimit,
		TelegramGlobal:   cfg.Telegram.GlobalLimit,
		MFAUser:          cfg.MFA.UserLimitPerMinute,
		MFAIP:            cfg.MFA.IPLimitPerMinute,
		MFAGlobal:        cfg.MFA.GlobalLimitPerMinute,
		BindingRequest:   cfg.EmailBinding.RequestsPerMinute,
		BindingConfirm:   cfg.EmailBinding.ConfirmationsPerMinute,
		InvitationActor:  cfg.Invitation.IssueActorAttemptsPerMinute,
		InvitationGlobal: cfg.Invitation.IssueProjectAttemptsPerMinute,
		ActivationGlobal: cfg.Invitation.ActivationGlobalLimit,
		TemporaryActor:   cfg.TemporaryPassword.IssueActorAttemptsPerMinute,
		TemporaryGlobal:  cfg.TemporaryPassword.IssueProjectAttemptsPerMinute,
		TemporarySetup:   cfg.TemporaryPassword.SetupProjectAttemptsPerMinute,
		JWTActor:         cfg.JWT.ActorPerMinute,
		JWTSession:       cfg.JWT.SessionPerMinute,
		JWTIP:            cfg.JWT.IPPerMinute,
		JWTGlobal:        cfg.JWT.ProjectPerMinute,
		JWTConsumer:      cfg.JWT.IntrospectionConsumerPerMinute,
		JWTIntrospection: cfg.JWT.IntrospectionProjectPerMinute,
	}
	if err := baseline.Validate(baseline); err != nil {
		return nil, err
	}
	store := repo.OperationBudgetsPolicy()
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
		cfg.OperationBudgetsSource = func(ctx context.Context) (domain.OperationBudgetsPolicy, error) {
			policy, err := load(ctx)
			if err != nil {
				return policy, err
			}
			return policy, policy.Validate(baseline)
		}
		bindOperationBudgets(cfg)
	}
	view := func(snapshot settingspostgres.PolicySnapshot[domain.OperationBudgetsPolicy]) settingshttp.OperationBudgetsPolicyView {
		return settingshttp.OperationBudgetsPolicyView{Version: snapshot.Version, Policy: settingshttp.OperationBudgetsPolicyDTO(snapshot.Policy), Source: mode.Metadata()}
	}
	return &settingshttp.OperationBudgetsPolicyHandler{
		Log: log,
		ReadPolicy: func(ctx context.Context, actor accessservice.Principal) (settingshttp.OperationBudgetsPolicyView, error) {
			snapshot, err := store.Read(ctx, actor)
			if mode == domain.SourceENV {
				snapshot.Policy = baseline
			}
			return view(snapshot), err
		},
		UpdatePolicy: func(ctx context.Context, actor accessservice.Principal, version int64, policy domain.OperationBudgetsPolicy) (settingshttp.OperationBudgetsPolicyView, error) {
			if err := policy.Validate(baseline); err != nil {
				return settingshttp.OperationBudgetsPolicyView{}, err
			}
			snapshot, err := store.Update(ctx, actor, version, policy)
			if err == nil {
				invalidate()
			}
			return view(snapshot), err
		},
	}, nil
}

func bindOperationBudgets(cfg *config.Config) {
	load := cfg.OperationBudgetsSource
	cfg.MFA.BudgetSource = func(ctx context.Context) (int, int, int, error) {
		p, err := load(ctx)
		return p.MFAUser, p.MFAIP, p.MFAGlobal, err
	}
	cfg.EmailBinding.BudgetSource = func(ctx context.Context) (int, int, int, error) {
		p, err := load(ctx)
		return p.BindingRequest, p.BindingConfirm, 0, err
	}
	cfg.Invitation.BudgetSource = func(ctx context.Context) (int, int, int, error) {
		p, err := load(ctx)
		return p.InvitationActor, p.InvitationGlobal, p.ActivationGlobal, err
	}
	cfg.TemporaryPassword.BudgetSource = func(ctx context.Context) (int, int, int, error) {
		p, err := load(ctx)
		return p.TemporaryActor, p.TemporaryGlobal, p.TemporarySetup, err
	}
}
