package account

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (p *ProjectEmail) ProvisionUser(ctx context.Context, input accountprovisioning.ProvisionInput) (*accountprovisioning.ProvisionResult, error) {
	if !p.cfg.Invitations.Enabled {
		return nil, accountdomain.ErrProvisionDisabled
	}
	var result *accountprovisioning.ProvisionResult
	err := p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		service := accountprovisioning.NewProvisioning(accountpostgres.New(pool), p.runtime.verificationLimits, p.runtime.verificationCipher, p.cfg.Invitations)
		var err error
		result, err = service.Provision(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectEmail) ReissueInvitation(ctx context.Context, input accountprovisioning.InvitationReissueInput) (*accountprovisioning.ProvisionResult, error) {
	if !p.cfg.Invitations.Enabled {
		return nil, accountdomain.ErrProvisionDisabled
	}
	var result *accountprovisioning.ProvisionResult
	err := p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		service := accountprovisioning.NewProvisioning(accountpostgres.New(pool), p.runtime.verificationLimits, p.runtime.verificationCipher, p.cfg.Invitations)
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
		service := passwordprovisioning.NewActivation(accountpostgres.New(pool), p.hash, p.runtime.resetLimits, p.runtime.resetCipher.Digest, p.cfg.Invitations)
		return service.Activate(ctx, token, password, confirmation, ip)
	})
}
