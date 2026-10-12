package access

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

type App struct {
	Service    *service.Service
	definition settings.Document
}

func New(ctx context.Context, pool *pgxpool.Pool, cfg settings.Config) (*App, error) {
	definition, err := settings.LoadFile(cfg.CatalogFile)
	if err != nil {
		return nil, err
	}
	catalog := definition.Catalog()
	repository := postgres.New(pool)
	permissions := catalog.Permissions()
	keys := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		keys = append(keys, string(permission.Key))
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := repository.CheckCatalog(ctx, keys); err != nil {
		return nil, err
	}
	return &App{Service: service.New(repository, catalog), definition: definition}, nil
}

func (a *App) Templates() []settings.RoleTemplate { return a.definition.Templates() }
