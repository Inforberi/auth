package profile

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	authsettings "github.com/Inforberi/financial-intelligence/internal/app/auth/settings"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func bindProjectFrontend(cfg runtimeprofile.ProjectProfileConfig, key projectruntime.Key, origin string, deps runtimeprofile.ProjectProfileDependencies) (runtimeprofile.ProjectProfileConfig, func(context.Context) (settings.FrontendPolicy, error)) {
	base := domain.FrontendDefaults(origin)
	load, _ := authsettings.CachedPolicy(func(ctx context.Context) (settings.FrontendPolicy, error) {
		var policy settings.FrontendPolicy
		err := deps.Registry.UsePool(ctx, key, func(ctx context.Context, pool *pgxpool.Pool) error {
			var err error
			policy, err = settingspg.ProjectFrontend(ctx, pool, base)
			if err != nil {
				return err
			}
			return domain.ValidateProjectFrontend(policy, origin, cfg.FrontendOrigins)
		})
		return policy, err
	})
	if cfg.Verification != nil {
		c := *cfg.Verification
		c.URLSource = func(ctx context.Context) (string, error) {
			p, err := load(ctx)
			return p.VerificationURL, err
		}
		cfg.Verification = &c
	}
	if cfg.Recovery != nil {
		c := *cfg.Recovery
		c.URLSource = func(ctx context.Context) (string, error) {
			p, err := load(ctx)
			return p.ResetURL, err
		}
		cfg.Recovery = &c
	}
	if cfg.EmailManagement != nil {
		c := *cfg.EmailManagement
		c.Invitations.URLSource = func(ctx context.Context) (string, error) {
			p, err := load(ctx)
			return p.InvitationURL, err
		}
		c.Change.URLSource = func(ctx context.Context) (string, string, string, error) {
			p, err := load(ctx)
			return p.EmailChangeURL, p.EmailChangeReportURL, p.EmailChangeRecoveryURL, err
		}
		cfg.EmailManagement = &c
	}
	return cfg, load
}
