package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (p *ProjectTokens) nativeEmailMFA(pool *pgxpool.Pool, service *tokenservice.Service) (*tokenservice.NativeLogin, error) {
	mfa, err := p.native.emailMFA.login(pool)
	if err != nil {
		return nil, err
	}
	return tokenservice.NewNativeLogin(service, mfa)
}

func (p *ProjectTokens) LoginPasswordEmailMFA(ctx context.Context, input tokenservice.NativePasswordInput) (*tokenservice.NativeLoginResult, error) {
	if p.native == nil || p.native.emailMFA == nil || !p.cfg.Native.PasswordEnabled {
		return nil, tokendomain.ErrNativeDisabled
	}
	var result *tokenservice.NativeLoginResult
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, service *tokenservice.Service) error {
		login, err := p.nativeEmailMFA(pool, service)
		if err != nil {
			return err
		}
		policy := settingsservice.New(settingspostgres.New(pool))
		passwords := passwordservice.New(passwordpostgres.New(pool), nil, p.deps.Hash, p.native.password).WithPublicPolicy(func(ctx context.Context, registration bool) error {
			return policy.CheckPublic(ctx, "password", registration)
		})
		passwordLogin, err := tokenservice.NewNativePasswordMFA(login, passwords)
		if err != nil {
			return err
		}
		result, err = passwordLogin.Login(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectTokens) CompleteNativeEmailMFA(ctx context.Context, input mfalogin.CompleteLoginInput) (*tokenservice.RefreshResult, error) {
	if p.native == nil || p.native.emailMFA == nil {
		return nil, tokendomain.ErrNativeDisabled
	}
	var result *tokenservice.RefreshResult
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, service *tokenservice.Service) error {
		login, err := p.nativeEmailMFA(pool, service)
		if err != nil {
			return err
		}
		result, err = login.Complete(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
