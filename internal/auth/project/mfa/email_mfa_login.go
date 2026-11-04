package mfa

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (p *ProjectEmailMFA) Start(ctx context.Context, proof mfaservice.PrimaryProof, ip string) (*mfalogin.LoginChallenge, error) {
	var result *mfalogin.LoginChallenge
	err := p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.Login(pool)
		if err != nil {
			return err
		}
		result, err = service.Start(ctx, proof, ip)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectEmailMFA) Complete(ctx context.Context, input mfalogin.CompleteLoginInput) (*mfalogin.LoginSession, error) {
	var result *mfalogin.LoginSession
	err := p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.Login(pool)
		if err != nil {
			return err
		}
		result, err = service.Complete(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
