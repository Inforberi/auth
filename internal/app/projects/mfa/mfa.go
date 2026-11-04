package mfa

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type ProjectMFA struct {
	factory    *ProjectMFALogin
	key        projectruntime.Key
	registry   *projectruntime.Registry
	reader     *runtimepostgres.RuntimeCredentialReader
	timeout    time.Duration
	emailProof bool
}

func (p *ProjectMFA) CompleteMFA(ctx context.Context, input mfalogin.CompleteLoginInput) (*mfalogin.LoginSession, error) {
	var result *mfalogin.LoginSession
	err := p.withMFA(ctx, func(ctx context.Context, login *mfalogin.Login) error {
		var err error
		result, err = login.Complete(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectMFA) StartMFAEnrollment(ctx context.Context, input mfalogin.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
	var result *mfaservice.Enrollment
	err := p.withMFA(ctx, func(ctx context.Context, login *mfalogin.Login) error {
		var err error
		result, err = login.StartRequiredEnrollment(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectMFA) ConfirmMFAEnrollment(ctx context.Context, input mfalogin.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
	var result *mfaservice.RecoveryCodes
	err := p.withMFA(ctx, func(ctx context.Context, login *mfalogin.Login) error {
		var err error
		result, err = login.ConfirmRequiredEnrollment(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectMFA) withMFA(ctx context.Context, use func(context.Context, *mfalogin.Login) error) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		login, err := p.factory.NewLogin(pool)
		if err != nil {
			return err
		}
		return use(ctx, login)
	})
}

func (p *ProjectMFA) use(ctx context.Context, use func(context.Context, *pgxpool.Pool) error) error {
	if p == nil || p.factory == nil {
		return mfadomain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return p.registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := projectapp.RequireCurrent(ctx, p.reader, p.key); err != nil {
			return err
		}
		if err := use(ctx, pool); err != nil {
			return err
		}
		return projectapp.RequireCurrent(ctx, p.reader, p.key)
	})
}
