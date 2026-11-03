package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type projectTemporary struct {
	limits passwordservice.RecoveryLimiter
	digest func(string) string
}

func (p *ProjectPassword) useTemporary(ctx context.Context, operation func(context.Context, *passwordprovisioning.TemporaryPasswordService) error) error {
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
		service := passwordprovisioning.NewTemporaryPassword(repo, p.hash, p.temporary.limits, p.temporary.digest, p.limits, p.cfg.TemporaryPassword)
		if err := operation(ctx, service); err != nil {
			return err
		}
		return p.requireCurrent(ctx)
	})
}

func (p *ProjectPassword) ProvisionTemporaryPassword(ctx context.Context, input passwordprovisioning.TemporaryProvisionInput) (*passwordprovisioning.TemporaryIssueResult, error) {
	var result *passwordprovisioning.TemporaryIssueResult
	err := p.useTemporary(ctx, func(ctx context.Context, service *passwordprovisioning.TemporaryPasswordService) error {
		var err error
		result, err = service.Provision(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) ReissueTemporaryPassword(ctx context.Context, input passwordprovisioning.TemporaryReissueInput) (*passwordprovisioning.TemporaryIssueResult, error) {
	var result *passwordprovisioning.TemporaryIssueResult
	err := p.useTemporary(ctx, func(ctx context.Context, service *passwordprovisioning.TemporaryPasswordService) error {
		var err error
		result, err = service.Reissue(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) BeginTemporaryPassword(ctx context.Context, email, password, ip string) (*passwordprovisioning.TemporaryLoginResult, error) {
	var result *passwordprovisioning.TemporaryLoginResult
	err := p.useTemporary(ctx, func(ctx context.Context, service *passwordprovisioning.TemporaryPasswordService) error {
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
	return p.useTemporary(ctx, func(ctx context.Context, service *passwordprovisioning.TemporaryPasswordService) error {
		return service.Complete(ctx, token, password, confirmation, ip)
	})
}
