package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func assembleAccessPolicy(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config) (*accessapp.App, *settingsservice.Service, *settingsservice.Providers, error) {
	access, err := accessapp.New(ctx, pool, cfg.Access, cfg.MFA.Enabled)
	if err != nil {
		return nil, nil, nil, err
	}
	service := settingsservice.New(settingspostgres.New(pool))
	snapshot, err := service.Initialize(ctx, cfg.InitialAuthPolicy())
	if err != nil {
		return nil, nil, nil, err
	}
	providers, err := assembleProviderSettings(ctx, pool, cfg, snapshot.Policy)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cfg.ConfigureAuthAdapters(snapshot.Policy); err != nil {
		return nil, nil, nil, err
	}
	service = settingsservice.New(settingspostgres.NewWithRuntime(pool, cfg.AvailableAuthMethods()))
	cfg.EmailOTP.CheckPolicy = func(ctx context.Context) error { return service.CheckPublic(ctx, "emailotp", false) }
	return access, service, providers, nil
}

func assembleRetentionSettings(ctx context.Context, pool *pgxpool.Pool, cfg accountservice.RetentionConfig) (*settingsservice.Retention, error) {
	service := settingsservice.NewRetention(settingspostgres.New(pool))
	err := service.Initialize(ctx, settingsdomain.RetentionPolicy{
		EmailReservationDays: cfg.EmailReservationDays, SessionDays: cfg.SessionDays, SecurityAuditDays: cfg.SecurityAuditDays,
	})
	return service, err
}
