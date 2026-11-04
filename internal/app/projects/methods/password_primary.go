package methods

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (p *ProjectPassword) Authenticate(ctx context.Context, input passwordservice.LoginInput) (mfaservice.PrimaryProof, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	var result mfaservice.PrimaryProof
	err := p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := p.requireCurrent(ctx); err != nil {
			return err
		}
		service, err := p.passwordService(pool, passwordpostgres.New(pool))
		if err != nil {
			return err
		}
		result, err = service.Authenticate(ctx, input)
		if err != nil {
			return err
		}
		return p.requireCurrent(ctx)
	})
	if err != nil {
		return mfaservice.PrimaryProof{}, err
	}
	return result, nil
}
