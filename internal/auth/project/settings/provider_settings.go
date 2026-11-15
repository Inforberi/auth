package settings

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsproviders "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type ProjectProviderSettings struct {
	binding          projectbinding.Binding
	google, telegram *secretbox.Cipher
}

func (s *ProjectProviderSettings) use(ctx context.Context, operation func(context.Context, *settingsproviders.Providers) (settingsdomain.ProviderSnapshot, error)) (settingsdomain.ProviderSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.binding
	var result settingsdomain.ProviderSnapshot
	err := p.Registry.UsePool(ctx, p.Key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectbinding.RequireCurrent(ctx, p.Reader, p.Key); err != nil {
			return err
		}
		var err error
		result, err = operation(ctx, settingsproviders.NewProviders(settingspostgres.New(pool), s.google, s.telegram))
		if err != nil {
			return err
		}
		return projectbinding.RequireCurrent(ctx, p.Reader, p.Key)
	})
	if err != nil {
		return settingsdomain.ProviderSnapshot{}, err
	}
	return result, nil
}

func (s *ProjectProviderSettings) Read(ctx context.Context, actor accessservice.Principal, name string) (settingsdomain.ProviderSnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsproviders.Providers) (settingsdomain.ProviderSnapshot, error) {
		return service.Read(ctx, actor, name)
	})
}

func (s *ProjectProviderSettings) Update(ctx context.Context, input settingsproviders.ProviderUpdateInput) (settingsdomain.ProviderSnapshot, error) {
	if s.google == nil || s.telegram == nil {
		return settingsdomain.ProviderSnapshot{}, projectdomain.ErrUnavailable
	}
	return s.use(ctx, func(ctx context.Context, service *settingsproviders.Providers) (settingsdomain.ProviderSnapshot, error) {
		return service.Update(ctx, input)
	})
}

func (s *ProjectProviderSettings) Configure(root string) error {
	scope, err := realmscope.New("project", string(s.binding.Key.Binding.ProjectID))
	if err == nil {

		s.google, err = secretbox.ForScope(scope, root, "provider-google:v1")
		if err == nil {
			s.telegram, err = secretbox.ForScope(scope, root, "provider-telegram:v1")
		}
	}

	return err
}

func (s *ProjectProviderSettings) PrepareUpdate(input settingsproviders.ProviderUpdateInput) (settingsproviders.ProviderUpdate, error) {
	if s.google == nil || s.telegram == nil {
		return settingsproviders.ProviderUpdate{}, projectdomain.ErrUnavailable
	}
	return settingsproviders.NewProviders(nil, s.google, s.telegram).PrepareUpdate(input)
}
