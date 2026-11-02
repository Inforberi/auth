package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type projectProviderSettings struct {
	profile          *ProjectProfile
	google, telegram *secretbox.Cipher
}

func (p *ProjectProfile) buildProfileProviderSettings(cfg ProjectProfileConfig, root string) {
	if !cfg.ProviderSettingsEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("provider_settings_read", "browser_disabled")
		p.state("provider_settings_write", "browser_disabled")
		return
	}
	s := &projectProviderSettings{profile: p}
	p.providerSettings = s
	p.state("provider_settings_read", "")
	if p.mfaManagement == nil {
		p.state("provider_settings_write", "mfa_unavailable")
		return
	}
	scope, err := realmscope.New("project", string(p.key.Binding.ProjectID))
	if err == nil {
		security := realmSecurity{scope: scope}
		s.google, err = security.cipher(root, "provider-google:v1")
		if err == nil {
			s.telegram, err = security.cipher(root, "provider-telegram:v1")
		}
	}
	p.feature("provider_settings_write", err)
}

func (s *projectProviderSettings) use(ctx context.Context, operation func(context.Context, *settingsservice.Providers) (settingsdomain.ProviderSnapshot, error)) (settingsdomain.ProviderSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.profile
	var result settingsdomain.ProviderSnapshot
	err := p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		var err error
		result, err = operation(ctx, settingsservice.NewProviders(settingspostgres.New(pool), s.google, s.telegram))
		if err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
	if err != nil {
		return settingsdomain.ProviderSnapshot{}, err
	}
	return result, nil
}

func (s *projectProviderSettings) Read(ctx context.Context, actor accessservice.Principal, name string) (settingsdomain.ProviderSnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsservice.Providers) (settingsdomain.ProviderSnapshot, error) {
		return service.Read(ctx, actor, name)
	})
}

func (s *projectProviderSettings) Update(ctx context.Context, input settingsservice.ProviderUpdateInput) (settingsdomain.ProviderSnapshot, error) {
	if s.google == nil || s.telegram == nil {
		return settingsdomain.ProviderSnapshot{}, projectdomain.ErrUnavailable
	}
	return s.use(ctx, func(ctx context.Context, service *settingsservice.Providers) (settingsdomain.ProviderSnapshot, error) {
		return service.Update(ctx, input)
	})
}
