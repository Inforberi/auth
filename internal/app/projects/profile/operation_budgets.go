package profile

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	authsettings "github.com/Inforberi/financial-intelligence/internal/app/auth/settings"
	methods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
)

func bindProjectOperationBudgets(cfg runtimeprofile.ProjectProfileConfig, key projectruntime.Key, deps runtimeprofile.ProjectProfileDependencies) runtimeprofile.ProjectProfileConfig {
	baseline := cfg.OperationBudgetBaseline
	if baseline.Validate(baseline) != nil {
		return cfg
	}
	load, _ := authsettings.CachedPolicy(func(ctx context.Context) (settings.OperationBudgetsPolicy, error) {
		var policy settings.OperationBudgetsPolicy
		err := deps.Registry.UsePool(ctx, key, func(ctx context.Context, pool *pgxpool.Pool) error {
			var err error
			policy, err = settingspg.New(pool).ProjectOperationBudgets(ctx, baseline)
			return err
		})
		return policy, err
	})
	mfaBudget := func(ctx context.Context) (int, int, int, error) {
		p, err := load(ctx)
		return p.MFAUser, p.MFAIP, p.MFAGlobal, err
	}
	if cfg.Password != nil {
		password := *cfg.Password
		password.MFA.BudgetSource = mfaBudget
		password.TemporaryPassword.BudgetSource = func(ctx context.Context) (int, int, int, error) {
			p, err := load(ctx)
			return p.TemporaryActor, p.TemporaryGlobal, p.TemporarySetup, err
		}
		cfg.Password = &password
	}
	if cfg.EmailOTP != nil {
		email := *cfg.EmailOTP
		email.MFA.BudgetSource = mfaBudget
		cfg.EmailOTP = &email
	}
	oidc := func(provider *methods.ProjectOIDCConfig) *methods.ProjectOIDCConfig {
		if provider == nil {
			return nil
		}
		copy := *provider
		copy.MFA.BudgetSource = mfaBudget
		copy.BudgetSource = func(ctx context.Context) (int, int, error) {
			p, err := load(ctx)
			if copy.Provider == "google" {
				return p.GoogleIP, p.GoogleGlobal, err
			}
			return p.TelegramIP, p.TelegramGlobal, err
		}
		return &copy
	}
	cfg.Google, cfg.Telegram = oidc(cfg.Google), oidc(cfg.Telegram)
	if cfg.EmailManagement != nil {
		email := *cfg.EmailManagement
		email.Binding.BudgetSource = func(ctx context.Context) (int, int, int, error) {
			p, err := load(ctx)
			return p.BindingRequest, p.BindingConfirm, 0, err
		}
		email.Invitations.BudgetSource = func(ctx context.Context) (int, int, int, error) {
			p, err := load(ctx)
			return p.InvitationActor, p.InvitationGlobal, p.ActivationGlobal, err
		}
		cfg.EmailManagement = &email
	}
	if cfg.Tokens != nil {
		tokens := *cfg.Tokens
		tokens.Native.MFA.BudgetSource = mfaBudget
		tokens.Limits.Source = func(ctx context.Context) (tokenredis.Limits, error) {
			p, err := load(ctx)
			return tokenredis.Limits{ActorPerMinute: p.JWTActor, SessionPerMinute: p.JWTSession, IPPerMinute: p.JWTIP, ProjectPerMinute: p.JWTGlobal}, err
		}
		if tokens.Introspection != nil {
			introspection := *tokens.Introspection
			introspection.BudgetSource = func(ctx context.Context) (int, int, error) {
				p, err := load(ctx)
				return p.JWTConsumer, p.JWTIntrospection, err
			}
			tokens.Introspection = &introspection
		}
		cfg.Tokens = &tokens
	}
	return cfg
}
