package mfa

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfarecovery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
)

type ProjectMFARecovery struct {
	mfa  *ProjectMFA
	mail *projectaccount.ProjectEmailRuntime
}

func (p *ProjectMFARecovery) use(ctx context.Context, operation func(context.Context, *mfarecovery.Recovery) error) error {
	if p == nil || p.mfa == nil || p.mail == nil {
		return domain.ErrUnavailable
	}
	return p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		repo := mfapostgres.New(pool)
		// Runtime may request/complete recovery, but must never approve it.
		if err := repo.CheckRecoveryOperator(ctx); err != nil {
			return domain.ErrUnavailable
		}
		if err := p.mail.CheckSMTP(ctx, pool); err != nil {
			return domain.ErrUnavailable
		}
		factory := p.mfa.factory
		service, err := mfarecovery.NewRecovery(repo, factory.cipher, totp.Authenticator{}, factory.limits, factory.managementConfig, factory.config.AllowPrimary)
		if err != nil {
			return err
		}
		return operation(ctx, service)
	})
}

func (p *ProjectMFARecovery) Start(ctx context.Context, input mfarecovery.StartRecoveryInput) (*mfarecovery.RecoveryCandidate, error) {
	var result *mfarecovery.RecoveryCandidate
	err := p.use(ctx, func(ctx context.Context, service *mfarecovery.Recovery) error {
		var err error
		result, err = service.Start(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectMFARecovery) Complete(ctx context.Context, input mfarecovery.CompleteRecoveryInput) (*mfaservice.RecoveryCodes, error) {
	var result *mfaservice.RecoveryCodes
	err := p.use(ctx, func(ctx context.Context, service *mfarecovery.Recovery) error {
		var err error
		result, err = service.Complete(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
