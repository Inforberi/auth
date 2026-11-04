package settings

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsproviders "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsretention "github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/service"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func AssemblePolicy(ctx context.Context, scope realmscope.Scope, pool *pgxpool.Pool, cfg *config.Config) (*accessapp.App, *settingsservice.Service, *settingsproviders.Providers, error) {
	if _, err := settingsservice.NewMFA(settingspostgres.New(pool), cfg.MFA.Enabled).Current(ctx); err != nil {
		return nil, nil, nil, err
	}
	access, err := accessapp.New(ctx, pool, cfg.Access, cfg.MFA.Enabled)
	if err != nil {
		return nil, nil, nil, err
	}
	service := settingsservice.New(settingspostgres.New(pool))
	snapshot, err := service.Initialize(ctx, cfg.InitialAuthPolicy())
	if err != nil {
		return nil, nil, nil, err
	}
	providers, err := assembleProviderSettings(ctx, scope, pool, cfg, snapshot.Policy)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cfg.ConfigureAuthAdapters(snapshot.Policy); err != nil {
		return nil, nil, nil, err
	}
	service = settingsservice.New(settingspostgres.NewWithRuntime(pool, cfg.AvailableAuthMethods(), settingsdomain.TokenIssuance{SessionExchange: cfg.JWT.Enabled, Native: cfg.JWT.Enabled && cfg.JWT.NativeEnabled}))
	cfg.EmailOTP.CheckPolicy = func(ctx context.Context) error { return service.CheckPublic(ctx, "emailotp", false) }
	return access, service, providers, nil
}

func AssembleRetention(ctx context.Context, pool *pgxpool.Pool, cfg accountservice.RetentionConfig) (*settingsretention.Retention, error) {
	service := settingsretention.NewRetention(settingspostgres.New(pool))
	err := service.Initialize(ctx, settingsdomain.RetentionPolicy{
		EmailReservationDays: cfg.EmailReservationDays, SessionDays: cfg.SessionDays, SecurityAuditDays: cfg.SecurityAuditDays,
	})
	return service, err
}
