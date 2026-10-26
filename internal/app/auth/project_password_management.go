package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (p *ProjectPassword) ChangePassword(ctx context.Context, user accountdomain.UserID, sessionHash, oldPassword, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	return p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := p.requireCurrent(ctx); err != nil {
			return err
		}
		if err := accountpostgres.New(pool).RequireVerified(ctx, user); err != nil {
			return err
		}
		passwords := passwordservice.New(passwordpostgres.New(pool), nil, p.hash, p.limits)
		if err := passwords.ChangePassword(ctx, user, sessionHash, oldPassword, newPassword); err != nil {
			return err
		}
		return p.requireCurrent(ctx)
	})
}

func (p *ProjectPassword) ConfirmReauthentication(ctx context.Context, user accountdomain.UserID, sessionHash, password, ip string) (*passwordservice.ReauthenticationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	var result *passwordservice.ReauthenticationResult
	err := p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := p.requireCurrent(ctx); err != nil {
			return err
		}
		service := passwordservice.NewReauthentication(passwordpostgres.New(pool), sessionpostgres.New(pool), p.hash, p.limits, tokengenerate.New(), p.cfg.Session.FreshAuthTTL)
		var err error
		result, err = service.Confirm(ctx, user, sessionHash, password, ip)
		if err != nil {
			return err
		}
		return p.requireCurrent(ctx)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
