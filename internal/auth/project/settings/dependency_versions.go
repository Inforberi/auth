package settings

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

// DependencyVersions borrows the selected project's pool for one readiness read.
// The caller owns its timeout and before/after comparison.
func DependencyVersions(ctx context.Context, registry *projectruntime.Registry, key projectruntime.Key) (settingsdomain.DependencyVersions, error) {
	var versions settingsdomain.DependencyVersions
	err := registry.UsePool(ctx, key, func(ctx context.Context, pool *pgxpool.Pool) error {
		var err error
		versions, err = settingspostgres.New(pool).DependencyVersions(ctx)
		return err
	})
	return versions, err
}
