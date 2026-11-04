package access

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
)

type ProjectAccess struct {
	binding  projectapp.Binding
	catalog  accesssettings.Catalog
	mfaReady bool
}

func (s *ProjectAccess) use(ctx context.Context, operation func(context.Context, *accessservice.Service) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.binding
	return p.Registry.UsePool(ctx, p.Key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectapp.RequireCurrent(ctx, p.Reader, p.Key); err != nil {
			return err
		}
		if err := operation(ctx, accessservice.New(accesspostgres.NewWithMFA(pool, s.mfaReady), s.catalog)); err != nil {
			return err
		}
		return projectapp.RequireCurrent(ctx, p.Reader, p.Key)
	})
}
