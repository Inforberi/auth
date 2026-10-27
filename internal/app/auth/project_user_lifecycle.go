package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

type projectUserLifecycle struct{ profile *ProjectProfile }

func (p *ProjectProfile) buildProfileUserLifecycle(cfg ProjectProfileConfig) {
	if !cfg.UserLifecycleEnabled {
		return
	}
	switch {
	case !cfg.BrowserEnabled:
		p.state("user_lifecycle", "browser_disabled")
	case p.mfaManagement == nil:
		p.state("user_lifecycle", "mfa_unavailable")
	default:
		p.userLifecycle = &projectUserLifecycle{profile: p}
		p.state("user_lifecycle", "")
	}
}

func (s *projectUserLifecycle) use(ctx context.Context, operation func(context.Context, *accountservice.UserLifecycle) (accountdomain.AuthVersion, error)) (accountdomain.AuthVersion, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.profile
	var version accountdomain.AuthVersion
	err := p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		var err error
		version, err = operation(ctx, accountservice.NewUserLifecycle(accountpostgres.New(pool)))
		if err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

func (s *projectUserLifecycle) ChangeStatus(ctx context.Context, actor accessservice.Principal, change accountdomain.StatusChange) (accountdomain.AuthVersion, error) {
	return s.use(ctx, func(ctx context.Context, lifecycle *accountservice.UserLifecycle) (accountdomain.AuthVersion, error) {
		return lifecycle.ChangeStatus(ctx, actor, change)
	})
}

func (s *projectUserLifecycle) Delete(ctx context.Context, actor accessservice.Principal, deletion accountdomain.AccountDeletion) (accountdomain.AuthVersion, error) {
	return s.use(ctx, func(ctx context.Context, lifecycle *accountservice.UserLifecycle) (accountdomain.AuthVersion, error) {
		return lifecycle.Delete(ctx, actor, deletion)
	})
}
