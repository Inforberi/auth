package account

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (p *ProjectEmail) useEmailChange(ctx context.Context, operation func(context.Context, *accountemail.EmailChangeService) error) error {
	if !p.cfg.Change.Enabled {
		return projectdomain.ErrUnavailable
	}
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		service := accountemail.NewEmailChange(accountpostgres.New(pool), p.hash, p.runtime.verificationLimits, p.runtime.verificationCipher, p.cfg.Change, p.cfg.FreshAuthTTL)
		return operation(ctx, service.WithFreshAuthSource(func(ctx context.Context) (time.Duration, error) {
			return settingspg.ProjectFreshAuth(ctx, pool, p.cfg.FreshAuthTTL)
		}))
	})
}

func (p *ProjectEmail) RequestEmailChange(ctx context.Context, user accountdomain.UserID, session, email, password, ip string) error {
	return p.useEmailChange(ctx, func(ctx context.Context, service *accountemail.EmailChangeService) error {
		return service.Request(ctx, user, session, email, password, ip)
	})
}

func (p *ProjectEmail) ConfirmEmailChange(ctx context.Context, token, ip string) error {
	return p.useEmailChange(ctx, func(ctx context.Context, service *accountemail.EmailChangeService) error {
		return service.Confirm(ctx, token, ip)
	})
}

func (p *ProjectEmail) ReportEmailChange(ctx context.Context, token, ip string) error {
	return p.useEmailChange(ctx, func(ctx context.Context, service *accountemail.EmailChangeService) error {
		return service.Report(ctx, token, ip)
	})
}

func (p *ProjectEmail) RecoverEmailChange(ctx context.Context, token, password, confirmation, ip string) error {
	if !p.cfg.Change.Enabled {
		return projectdomain.ErrUnavailable
	}
	return p.runtime.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		service := passwordrecovery.NewProtectedRecovery(accountpostgres.New(pool), p.runtime.recovery(pool, mail, p.hash, p.cfg.Password))
		return service.Recover(ctx, token, password, confirmation, ip)
	})
}
