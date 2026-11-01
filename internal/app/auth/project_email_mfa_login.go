package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (p *projectEmailMFA) Start(ctx context.Context, proof mfaservice.PrimaryProof, ip string) (*mfaservice.LoginChallenge, error) {
	var result *mfaservice.LoginChallenge
	err := p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.login(pool)
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

func (p *projectEmailMFA) Complete(ctx context.Context, input mfaservice.CompleteLoginInput) (*mfaservice.LoginSession, error) {
	var result *mfaservice.LoginSession
	err := p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.login(pool)
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
