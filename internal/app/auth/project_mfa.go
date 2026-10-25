package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (p *ProjectPassword) CompleteMFA(ctx context.Context, input mfaservice.CompleteLoginInput) (*mfaservice.LoginSession, error) {
	var result *mfaservice.LoginSession
	err := p.withMFA(ctx, func(ctx context.Context, login *mfaservice.Login) error {
		var err error
		result, err = login.Complete(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) StartMFAEnrollment(ctx context.Context, input mfaservice.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
	var result *mfaservice.Enrollment
	err := p.withMFA(ctx, func(ctx context.Context, login *mfaservice.Login) error {
		var err error
		result, err = login.StartRequiredEnrollment(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) ConfirmMFAEnrollment(ctx context.Context, input mfaservice.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
	var result *mfaservice.RecoveryCodes
	err := p.withMFA(ctx, func(ctx context.Context, login *mfaservice.Login) error {
		var err error
		result, err = login.ConfirmRequiredEnrollment(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectPassword) withMFA(ctx context.Context, use func(context.Context, *mfaservice.Login) error) error {
	if p.mfa == nil {
		return mfadomain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	return p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := p.requireCurrent(ctx); err != nil {
			return err
		}
		login, err := p.mfa.newLogin(pool)
		if err != nil {
			return err
		}
		if err := use(ctx, login); err != nil {
			return err
		}
		return p.requireCurrent(ctx)
	})
}
