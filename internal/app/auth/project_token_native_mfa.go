package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (p *ProjectTokens) CompleteNativeMFA(ctx context.Context, input mfaservice.CompleteLoginInput) (*tokenservice.RefreshResult, error) {
	if p.native == nil {
		return nil, tokendomain.ErrNativeDisabled
	}
	var result *tokenservice.RefreshResult
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, service *tokenservice.Service) error {
		login, _, err := p.nativeLogin(pool, service)
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

func (p *ProjectTokens) StartNativeEnrollment(ctx context.Context, input mfaservice.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
	if p.native == nil {
		return nil, tokendomain.ErrNativeDisabled
	}
	var result *mfaservice.Enrollment
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, service *tokenservice.Service) error {
		_, mfa, err := p.nativeLogin(pool, service)
		if err != nil {
			return err
		}
		result, err = mfa.StartNativeRequiredEnrollment(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectTokens) ConfirmNativeEnrollment(ctx context.Context, input mfaservice.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
	if p.native == nil {
		return nil, tokendomain.ErrNativeDisabled
	}
	var result *mfaservice.RecoveryCodes
	err := p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, service *tokenservice.Service) error {
		_, mfa, err := p.nativeLogin(pool, service)
		if err != nil {
			return err
		}
		result, err = mfa.ConfirmNativeRequiredEnrollment(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
