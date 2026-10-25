package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (p *ProjectEmail) ProvisionUser(ctx context.Context, input accountservice.ProvisionInput) (*accountservice.ProvisionResult, error) {
	if !p.cfg.Invitations.Enabled {
		return nil, accountdomain.ErrProvisionDisabled
	}
	var result *accountservice.ProvisionResult
	err := p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		service := accountservice.NewProvisioning(accountpostgres.New(pool), p.runtime.verification(pool, mail, p.cfg.Verification), p.cfg.Invitations)
		var err error
		result, err = service.Provision(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectEmail) ReissueInvitation(ctx context.Context, input accountservice.InvitationReissueInput) (*accountservice.ProvisionResult, error) {
	if !p.cfg.Invitations.Enabled {
		return nil, accountdomain.ErrProvisionDisabled
	}
	var result *accountservice.ProvisionResult
	err := p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		service := accountservice.NewProvisioning(accountpostgres.New(pool), p.runtime.verification(pool, mail, p.cfg.Verification), p.cfg.Invitations)
		var err error
		result, err = service.ReissueInvitation(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectEmail) ActivateInvitation(ctx context.Context, token, password, confirmation, ip string) error {
	if !p.cfg.Invitations.Enabled {
		return accountdomain.ErrProvisionDisabled
	}
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		service := passwordservice.NewActivation(accountpostgres.New(pool), p.runtime.recovery(pool, mail, p.hash, p.cfg.Password), p.cfg.Invitations)
		return service.Activate(ctx, token, password, confirmation, ip)
	})
}
