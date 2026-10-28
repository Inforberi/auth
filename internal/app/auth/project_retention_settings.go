package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type projectRetentionSettings struct{ profile *ProjectProfile }

func (p *ProjectProfile) buildProfileRetentionSettings(cfg ProjectProfileConfig) {
	if !cfg.RetentionSettingsEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("retention_settings_read", "browser_disabled")
		p.state("retention_settings_write", "browser_disabled")
		return
	}
	p.retentionSettings = &projectRetentionSettings{profile: p}
	p.state("retention_settings_read", "")
	reason := ""
	if p.mfaManagement == nil {
		reason = "mfa_unavailable"
	}
	p.state("retention_settings_write", reason)
}

func (s *projectRetentionSettings) use(ctx context.Context, operation func(context.Context, *settingsservice.Retention) (settingsdomain.RetentionSnapshot, error)) (settingsdomain.RetentionSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.profile
	var result settingsdomain.RetentionSnapshot
	err := p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		var err error
		result, err = operation(ctx, settingsservice.NewRetention(settingspostgres.New(pool)))
		if err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
	if err != nil {
		return settingsdomain.RetentionSnapshot{}, err
	}
	return result, nil
}

func (s *projectRetentionSettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.RetentionSnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsservice.Retention) (settingsdomain.RetentionSnapshot, error) {
		return service.Read(ctx, actor)
	})
}

func (s *projectRetentionSettings) Update(ctx context.Context, input settingsservice.RetentionUpdateInput) (settingsdomain.RetentionSnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsservice.Retention) (settingsdomain.RetentionSnapshot, error) {
		return service.Update(ctx, input)
	})
}
