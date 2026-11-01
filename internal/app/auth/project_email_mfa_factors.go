package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (p *projectEmailMFA) Status(ctx context.Context, proof mfaservice.Proof) (*domain.EmailFactor, error) {
	var result *domain.EmailFactor
	err := p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.factors(pool)
		if err != nil {
			return err
		}
		result, err = service.Status(ctx, proof)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *projectEmailMFA) Enable(ctx context.Context, proof mfaservice.Proof) error {
	return p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.factors(pool)
		if err != nil {
			return err
		}
		return service.Enable(ctx, proof)
	})
}

func (p *projectEmailMFA) Disable(ctx context.Context, proof mfaservice.Proof) error {
	return p.mfa.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.factors(pool)
		if err != nil {
			return err
		}
		return service.Disable(ctx, proof)
	})
}
