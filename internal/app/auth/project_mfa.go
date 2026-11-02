package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type projectMFA struct {
	factory    *projectMFALogin
	key        projectruntime.Key
	registry   *projectruntime.Registry
	reader     *runtimepostgres.RuntimeCredentialReader
	timeout    time.Duration
	emailProof bool
}

func (p *projectMFA) CompleteMFA(ctx context.Context, input mfaservice.CompleteLoginInput) (*mfaservice.LoginSession, error) {
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

func (p *projectMFA) StartMFAEnrollment(ctx context.Context, input mfaservice.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
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

func (p *projectMFA) ConfirmMFAEnrollment(ctx context.Context, input mfaservice.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
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

func (p *projectMFA) withMFA(ctx context.Context, use func(context.Context, *mfaservice.Login) error) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		login, err := p.factory.newLogin(pool)
		if err != nil {
			return err
		}
		return use(ctx, login)
	})
}

func (p *projectMFA) use(ctx context.Context, use func(context.Context, *pgxpool.Pool) error) error {
	if p == nil || p.factory == nil {
		return mfadomain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.reader, p.key); err != nil {
			return err
		}
		if err := use(ctx, pool); err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.reader, p.key)
	})
}
