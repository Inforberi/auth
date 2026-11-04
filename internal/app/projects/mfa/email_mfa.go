package mfa

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	projectaccount "github.com/Inforberi/financial-intelligence/internal/app/projects/account"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type ProjectEmailMFAConfig struct {
	Preparation otpservice.EmailPreparationConfig
	Factors     mfamanagement.EmailFactorConfig
}

func (c ProjectEmailMFAConfig) Validate() error {
	if err := c.Preparation.Validate(); err != nil {
		return err
	}
	return c.Factors.Validate()
}

type ProjectEmailMFA struct {
	mfa  *ProjectMFA
	mail *projectaccount.ProjectEmailRuntime
	cfg  ProjectEmailMFAConfig
}

func (p *ProjectEmailMFA) preparation(pool *pgxpool.Pool) (*otpservice.EmailPreparation, error) {
	return p.mail.NewEmailPreparation(pool, p.cfg.Preparation)
}

func (p *ProjectEmailMFA) factors(pool *pgxpool.Pool) (*mfamanagement.EmailFactors, error) {
	factory := p.mfa.factory
	return mfamanagement.NewConfiguredEmailFactors(mfapostgres.New(pool), factory.cipher, factory.limits, p.cfg.Factors)
}

func (p *ProjectEmailMFA) Login(pool *pgxpool.Pool) (*otpservice.EmailLogin, error) {
	factory := p.mfa.factory
	return p.mail.NewFactorLogin(pool, factory.cipher, factory.limits, factory.config)
}

func (p *ProjectEmailMFA) Request(ctx context.Context, proof mfaservice.Proof, email, ip string) (*otpservice.RequestedCode, error) {
	var result *otpservice.RequestedCode
	err := p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.preparation(pool)
		if err != nil {
			return err
		}
		result, err = service.Request(ctx, proof, email, ip)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectEmailMFA) Confirm(ctx context.Context, input otpservice.EmailPreparationConfirmation) (*otpservice.ReauthenticatedSession, error) {
	var result *otpservice.ReauthenticatedSession
	err := p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.preparation(pool)
		if err != nil {
			return err
		}
		result, err = service.Confirm(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
