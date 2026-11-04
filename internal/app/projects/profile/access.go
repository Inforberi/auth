package profile

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectaccess "github.com/Inforberi/financial-intelligence/internal/app/projects/access"
)

func (p *ProjectProfile) buildProfileAccess(ctx context.Context, cfg ProjectProfileConfig) {
	if cfg.Access == nil {
		return
	}
	reason := ""
	switch {
	case !cfg.BrowserEnabled:
		reason = "browser_disabled"
	case !cfg.Access.Contains(accesssettings.RolesManage):
		reason = "invalid_catalog"
	default:
		permissions := cfg.Access.Permissions()
		keys := make([]string, 0, len(permissions))
		for _, permission := range permissions {
			keys = append(keys, string(permission.Key))
		}
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		err := p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
			return accesspostgres.New(pool).CheckCatalog(ctx, keys)
		})
		if err != nil {
			reason = "catalog_unavailable"
		}
	}
	p.state("access_read", reason)
	if reason != "" {
		p.state("access_write", reason)
		return
	}
	p.access = projectaccess.NewProjectAccess(p.runtimeBinding(), *cfg.Access, p.mfaManagement != nil)
	if p.mfaManagement == nil {
		reason = "mfa_unavailable"
	}
	p.state("access_write", reason)
}
