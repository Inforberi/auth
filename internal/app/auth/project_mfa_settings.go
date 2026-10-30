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

type projectMFASettings struct{ profile *ProjectProfile }

func (p *ProjectProfile) buildProfileMFASettings(cfg ProjectProfileConfig) {
	if !cfg.MFASettingsEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("mfa_settings", "browser_disabled")
		return
	}
	p.mfaSettings = &projectMFASettings{profile: p}
	p.state("mfa_settings", "")
}

func (s *projectMFASettings) use(ctx context.Context, operation func(context.Context, *settingsservice.MFA) (settingsdomain.MFASnapshot, error)) (settingsdomain.MFASnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.profile
	var result settingsdomain.MFASnapshot
	err := p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		var err error
		result, err = operation(ctx, settingsservice.NewMFA(settingspostgres.New(pool), p.mfaManagement != nil))
		if err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
	if err != nil {
		return settingsdomain.MFASnapshot{}, err
	}
	return result, nil
}

func (s *projectMFASettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.MFASnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsservice.MFA) (settingsdomain.MFASnapshot, error) {
		return service.Read(ctx, actor)
	})
}

func (s *projectMFASettings) Update(ctx context.Context, input settingsservice.MFAUpdateInput) (settingsdomain.MFASnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsservice.MFA) (settingsdomain.MFASnapshot, error) {
		return service.Update(ctx, input)
	})
}
