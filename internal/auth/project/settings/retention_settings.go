package settings

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsretention "github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/service"
)

type ProjectRetentionSettings struct{ binding projectbinding.Binding }

func (s *ProjectRetentionSettings) use(ctx context.Context, operation func(context.Context, *settingsretention.Retention) (settingsdomain.RetentionSnapshot, error)) (settingsdomain.RetentionSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.binding
	var result settingsdomain.RetentionSnapshot
	err := p.Registry.UsePool(ctx, p.Key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectbinding.RequireCurrent(ctx, p.Reader, p.Key); err != nil {
			return err
		}
		var err error
		result, err = operation(ctx, settingsretention.NewRetention(settingspostgres.New(pool)))
		if err != nil {
			return err
		}
		return projectbinding.RequireCurrent(ctx, p.Reader, p.Key)
	})
	if err != nil {
		return settingsdomain.RetentionSnapshot{}, err
	}
	return result, nil
}

func (s *ProjectRetentionSettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.RetentionSnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsretention.Retention) (settingsdomain.RetentionSnapshot, error) {
		return service.Read(ctx, actor)
	})
}

func (s *ProjectRetentionSettings) Update(ctx context.Context, input settingsretention.RetentionUpdateInput) (settingsdomain.RetentionSnapshot, error) {
	return s.use(ctx, func(ctx context.Context, service *settingsretention.Retention) (settingsdomain.RetentionSnapshot, error) {
		return service.Update(ctx, input)
	})
}
