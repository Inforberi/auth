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

type projectUserDirectory struct{ profile *ProjectProfile }

func (p *ProjectProfile) buildProfileUserDirectory(cfg ProjectProfileConfig) {
	if !cfg.UserDirectoryEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("user_directory", "browser_disabled")
		return
	}
	p.userDirectory = &projectUserDirectory{profile: p}
	p.state("user_directory", "")
}

func (s *projectUserDirectory) use(ctx context.Context, operation func(context.Context, *accountservice.UserDirectory) error) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	p := s.profile
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		if err := operation(ctx, accountservice.NewUserDirectory(accountpostgres.New(pool))); err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
}

func (s *projectUserDirectory) List(ctx context.Context, actor accessservice.Principal, input accountservice.UserListInput) (accountservice.UserPage, error) {
	var result accountservice.UserPage
	err := s.use(ctx, func(ctx context.Context, directory *accountservice.UserDirectory) error {
		var err error
		result, err = directory.List(ctx, actor, input)
		return err
	})
	if err != nil {
		return accountservice.UserPage{}, err
	}
	return result, nil
}

func (s *projectUserDirectory) Read(ctx context.Context, actor accessservice.Principal, id accountdomain.UserID) (accountservice.UserDetail, error) {
	var result accountservice.UserDetail
	err := s.use(ctx, func(ctx context.Context, directory *accountservice.UserDirectory) error {
		var err error
		result, err = directory.Read(ctx, actor, id)
		return err
	})
	if err != nil {
		return accountservice.UserDetail{}, err
	}
	return result, nil
}
