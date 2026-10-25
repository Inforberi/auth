package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (p *ProjectTokens) Exchange(ctx context.Context, input tokenservice.ExchangeInput) (*tokenservice.ExchangeResult, error) {
	var result *tokenservice.ExchangeResult
	err := p.use(ctx, func(ctx context.Context, _ *pgxpool.Pool, service *tokenservice.Service) error {
		var err error
		result, err = service.Exchange(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectTokens) Refresh(ctx context.Context, input tokenservice.RefreshInput) (*tokenservice.RefreshResult, error) {
	var result *tokenservice.RefreshResult
	err := p.use(ctx, func(ctx context.Context, _ *pgxpool.Pool, service *tokenservice.Service) error {
		var err error
		result, err = service.Refresh(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectTokens) Logout(ctx context.Context, input tokenservice.RefreshInput) error {
	return p.use(ctx, func(ctx context.Context, _ *pgxpool.Pool, service *tokenservice.Service) error {
		return service.Logout(ctx, input)
	})
}

func (p *ProjectTokens) PublicJWKS(ctx context.Context) ([]byte, error) {
	var result []byte
	err := p.use(ctx, func(_ context.Context, _ *pgxpool.Pool, _ *tokenservice.Service) error {
		result = p.signer.PublicJWKS()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
