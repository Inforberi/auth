package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
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

type projectEmailMFA struct {
	mfa  *projectMFA
	mail *projectEmailRuntime
	cfg  ProjectEmailMFAConfig
}

func (p *projectEmailMFA) preparation(pool *pgxpool.Pool) (*otpservice.EmailPreparation, error) {
	return otpservice.NewEmailPreparation(otppostgres.New(pool), p.mail.otpCipher, p.mail.resetLimits, tokengenerate.New(), p.cfg.Preparation)
}

func (p *projectEmailMFA) factors(pool *pgxpool.Pool) (*mfamanagement.EmailFactors, error) {
	factory := p.mfa.factory
	return mfamanagement.NewConfiguredEmailFactors(mfapostgres.New(pool), factory.cipher, factory.limits, p.cfg.Factors)
}

func (p *projectEmailMFA) login(pool *pgxpool.Pool) (*otpservice.EmailLogin, error) {
	factory := p.mfa.factory
	return otpservice.NewEmailLogin(mfapostgres.New(pool), p.mail.otpCipher, factory.cipher, factory.limits, tokengenerate.New(), factory.config)
}

func (p *projectEmailMFA) Request(ctx context.Context, proof mfaservice.Proof, email, ip string) (*otpservice.RequestedCode, error) {
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

func (p *projectEmailMFA) Confirm(ctx context.Context, input otpservice.EmailPreparationConfirmation) (*otpservice.ReauthenticatedSession, error) {
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
