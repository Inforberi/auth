package account

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
)

type ProjectUserLifecycle struct{ binding projectbinding.Binding }

func (s *ProjectUserLifecycle) use(ctx context.Context, operation func(context.Context, *accountservice.UserLifecycle) (accountdomain.AuthVersion, error)) (accountdomain.AuthVersion, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.binding
	var version accountdomain.AuthVersion
	err := p.Registry.UsePool(ctx, p.Key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectbinding.RequireCurrent(ctx, p.Reader, p.Key); err != nil {
			return err
		}
		var err error
		version, err = operation(ctx, accountservice.NewUserLifecycle(accountpostgres.New(pool)))
		if err != nil {
			return err
		}
		return projectbinding.RequireCurrent(ctx, p.Reader, p.Key)
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

func (s *ProjectUserLifecycle) ChangeStatus(ctx context.Context, actor accessservice.Principal, change accountdomain.StatusChange) (accountdomain.AuthVersion, error) {
	return s.use(ctx, func(ctx context.Context, lifecycle *accountservice.UserLifecycle) (accountdomain.AuthVersion, error) {
		return lifecycle.ChangeStatus(ctx, actor, change)
	})
}

func (s *ProjectUserLifecycle) Delete(ctx context.Context, actor accessservice.Principal, deletion accountdomain.AccountDeletion) (accountdomain.AuthVersion, error) {
	return s.use(ctx, func(ctx context.Context, lifecycle *accountservice.UserLifecycle) (accountdomain.AuthVersion, error) {
		return lifecycle.Delete(ctx, actor, deletion)
	})
}
