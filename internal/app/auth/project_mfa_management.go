package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (p *projectMFA) withManagement(ctx context.Context, use func(context.Context, *mfaservice.Service) error) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		repo := mfapostgres.NewWithEmailProof(pool, p.emailProof)
		service, err := mfaservice.NewConfigured(repo, p.factory.cipher, mfatotp.Authenticator{}, p.factory.limits, tokengenerate.New(), p.factory.managementConfig)
		if err != nil {
			return err
		}
		return use(ctx, service)
	})
}

func (p *projectMFA) Status(ctx context.Context, proof mfaservice.Proof) (*mfaservice.SecurityStatus, error) {
	var result *mfaservice.SecurityStatus
	err := p.withManagement(ctx, func(ctx context.Context, service *mfaservice.Service) error {
		var err error
		result, err = service.Status(ctx, proof)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *projectMFA) StepUp(ctx context.Context, input mfaservice.StepUpInput) (*mfaservice.StepUpResult, error) {
	var result *mfaservice.StepUpResult
	err := p.withManagement(ctx, func(ctx context.Context, service *mfaservice.Service) error {
		var err error
		result, err = service.StepUp(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *projectMFA) Disable(ctx context.Context, proof mfaservice.Proof) error {
	return p.withManagement(ctx, func(ctx context.Context, service *mfaservice.Service) error {
		return service.Disable(ctx, proof)
	})
}

func (p *projectMFA) RegenerateRecovery(ctx context.Context, proof mfaservice.Proof) (*mfaservice.RecoveryCodes, error) {
	var result *mfaservice.RecoveryCodes
	err := p.withManagement(ctx, func(ctx context.Context, service *mfaservice.Service) error {
		var err error
		result, err = service.RegenerateRecovery(ctx, proof)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
