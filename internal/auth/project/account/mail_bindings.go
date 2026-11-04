package account

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (p *ProjectEmailRuntime) NewEmailPreparation(pool *pgxpool.Pool, cfg otpservice.EmailPreparationConfig) (*otpservice.EmailPreparation, error) {
	return otpservice.NewEmailPreparation(otppostgres.New(pool), p.otpCipher, p.resetLimits, tokengenerate.New(), cfg)
}

func (p *ProjectEmailRuntime) NewFactorLogin(pool *pgxpool.Pool, cipher mfaservice.Cipher, limits mfaservice.Limiter, cfg mfaservice.LoginConfig) (*otpservice.EmailLogin, error) {
	return otpservice.NewEmailLogin(mfapostgres.New(pool), p.otpCipher, cipher, limits, tokengenerate.New(), cfg)
}

func (p *ProjectEmailRuntime) CheckSMTP(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := p.smtp.CredentialsInPool(ctx, pool)
	return err
}

func (p *ProjectEmailRuntime) CheckSMTPConfiguration(ctx context.Context) error {
	_, err := p.smtp.Credentials(ctx)
	return err
}

func (p *ProjectEmailRuntime) DeliverReset(ctx context.Context) error { return p.deliver(ctx, false) }

func NewStoredProjectEmail(ctx context.Context, key projectruntime.Key, cfg ProjectEmailConfig, allowed []string, deps ProjectEmailDependencies) (*ProjectEmail, error) {
	return newProjectEmail(ctx, key, cfg, allowed, deps, false)
}
