package access

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
)

type ProjectAccess struct {
	binding  projectbinding.Binding
	catalog  accesssettings.Catalog
	mfaReady bool
}

func (s *ProjectAccess) use(ctx context.Context, operation func(context.Context, *accessservice.Service) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.binding
	return p.Registry.UsePool(ctx, p.Key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectbinding.RequireCurrent(ctx, p.Reader, p.Key); err != nil {
			return err
		}
		if err := operation(ctx, accessservice.New(accesspostgres.NewWithMFA(pool, s.mfaReady), s.catalog)); err != nil {
			return err
		}
		return projectbinding.RequireCurrent(ctx, p.Reader, p.Key)
	})
}
