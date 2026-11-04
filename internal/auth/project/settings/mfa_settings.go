package settings

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type ProjectMFASettings struct {
	binding projectbinding.Binding
	ready   bool
}

func (s *ProjectMFASettings) use(ctx context.Context, operation func(context.Context, *settingsservice.MFA) (settingsdomain.MFASnapshot, error)) (settingsdomain.MFASnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.binding
	var result settingsdomain.MFASnapshot
	err := p.Registry.UsePool(ctx, p.Key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectbinding.RequireCurrent(ctx, p.Reader, p.Key); err != nil {
			return err
		}
		var err error
		result, err = operation(ctx, settingsservice.NewMFA(settingspostgres.New(pool), s.ready))
		if err != nil {
			return err
		}
		return projectbinding.RequireCurrent(ctx, p.Reader, p.Key)
	})
	if err != nil {
		return settingsdomain.MFASnapshot{}, err
	}
	return result, nil
}

func (s *ProjectMFASettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.MFASnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsservice.MFA) (settingsdomain.MFASnapshot, error) {
		return service.Read(ctx, actor)
	})
}

func (s *ProjectMFASettings) Update(ctx context.Context, input settingsservice.MFAUpdateInput) (settingsdomain.MFASnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsservice.MFA) (settingsdomain.MFASnapshot, error) {
		return service.Update(ctx, input)
	})
}
