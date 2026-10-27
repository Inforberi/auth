package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
)

type projectAccess struct {
	profile  *ProjectProfile
	catalog  accesssettings.Catalog
	mfaReady bool
}

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
	p.access = &projectAccess{profile: p, catalog: *cfg.Access, mfaReady: p.mfaManagement != nil}
	if !p.access.mfaReady {
		reason = "mfa_unavailable"
	}
	p.state("access_write", reason)
}

func (s *projectAccess) use(ctx context.Context, operation func(context.Context, *accessservice.Service) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.profile
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		if err := operation(ctx, accessservice.New(accesspostgres.NewWithMFA(pool, s.mfaReady), s.catalog)); err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
}
