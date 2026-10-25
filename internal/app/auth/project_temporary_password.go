package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type projectTemporary struct {
	limits passwordservice.RecoveryLimiter
	digest func(string) string
}

func (p *ProjectPassword) useTemporary(ctx context.Context, operation func(context.Context, *passwordservice.TemporaryPasswordService) error) error {
	if p.temporary == nil {
		return passworddomain.ErrTemporaryPasswordDisabled
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	return p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := p.requireCurrent(ctx); err != nil {
			return err
		}
		account := accountpostgres.New(pool)
		repo := passwordpostgres.NewTemporaryPassword(pool, account.ProvisionInTransaction)
		service := passwordservice.NewTemporaryPassword(repo, p.hash, p.temporary.limits, p.temporary.digest, p.limits, p.cfg.TemporaryPassword)
		if err := operation(ctx, service); err != nil {
			return err
		}
		return p.requireCurrent(ctx)
	})
}

func (p *ProjectPassword) ProvisionTemporaryPassword(ctx context.Context, input passwordservice.TemporaryProvisionInput) (*passwordservice.TemporaryIssueResult, error) {
	var result *passwordservice.TemporaryIssueResult
	err := p.useTemporary(ctx, func(ctx context.Context, service *passwordservice.TemporaryPasswordService) error {
		var err error
		result, err = service.Provision(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) ReissueTemporaryPassword(ctx context.Context, input passwordservice.TemporaryReissueInput) (*passwordservice.TemporaryIssueResult, error) {
	var result *passwordservice.TemporaryIssueResult
	err := p.useTemporary(ctx, func(ctx context.Context, service *passwordservice.TemporaryPasswordService) error {
		var err error
		result, err = service.Reissue(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) BeginTemporaryPassword(ctx context.Context, email, password, ip string) (*passwordservice.TemporaryLoginResult, error) {
	var result *passwordservice.TemporaryLoginResult
	err := p.useTemporary(ctx, func(ctx context.Context, service *passwordservice.TemporaryPasswordService) error {
		var err error
		result, err = service.Login(ctx, email, password, ip)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) CompleteTemporaryPassword(ctx context.Context, token, password, confirmation, ip string) error {
	return p.useTemporary(ctx, func(ctx context.Context, service *passwordservice.TemporaryPasswordService) error {
		return service.Complete(ctx, token, password, confirmation, ip)
	})
}
