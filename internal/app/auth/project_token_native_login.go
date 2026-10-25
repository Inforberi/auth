package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (p *ProjectTokens) LoginPassword(ctx context.Context, input tokenservice.NativePasswordInput) (*tokenservice.NativeLoginResult, error) {
	if p.native == nil || !p.cfg.Native.PasswordEnabled {
		return nil, tokendomain.ErrNativeDisabled
	}
	var result *tokenservice.NativeLoginResult
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, service *tokenservice.Service) error {
		login, err := p.nativePassword(pool, service)
		if err != nil {
			return err
		}
		result, err = login.Login(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectTokens) RequestEmail(ctx context.Context, email, ip, audience string, scope []accessdomain.PermissionKey) (*otpservice.RequestedCode, error) {
	if p.native == nil || !p.cfg.Native.EmailOTP.Enabled {
		return nil, tokendomain.ErrNativeDisabled
	}
	var result *otpservice.RequestedCode
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, service *tokenservice.Service) error {
		login, err := p.nativeEmail(pool, service)
		if err != nil {
			return err
		}
		result, err = login.Request(ctx, email, ip, audience, scope)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectTokens) ConfirmEmail(ctx context.Context, input otpservice.ConfirmInput) (*tokenservice.NativeLoginResult, error) {
	if p.native == nil || !p.cfg.Native.EmailOTP.Enabled {
		return nil, tokendomain.ErrNativeDisabled
	}
	var result *tokenservice.NativeLoginResult
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, service *tokenservice.Service) error {
		login, err := p.nativeEmail(pool, service)
		if err != nil {
			return err
		}
		result, err = login.Confirm(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
