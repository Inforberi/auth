package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (p *ProjectEmail) RequestEmailBinding(ctx context.Context, input accountemail.EmailBindingInput) (time.Time, error) {
	if !p.cfg.Binding.Enabled {
		return time.Time{}, accountdomain.ErrEmailBindingDisabled
	}
	var expires time.Time
	err := p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, _ *mailer.Mailer) error {
		service := accountemail.NewEmailBinding(accountpostgres.New(pool), p.runtime.verificationLimits, p.runtime.verificationCipher, p.cfg.Binding)
		var err error
		expires, err = service.Request(ctx, input)
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	return expires, nil
}

func (p *ProjectEmail) ConfirmEmailBinding(ctx context.Context, proof mfaservice.Proof, code, ip string) error {
	if !p.cfg.Binding.Enabled {
		return accountdomain.ErrEmailBindingDisabled
	}
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, _ *mailer.Mailer) error {
		service := accountemail.NewEmailBinding(accountpostgres.New(pool), p.runtime.verificationLimits, p.runtime.verificationCipher, p.cfg.Binding)
		return service.Confirm(ctx, proof, code, ip)
	})
}
