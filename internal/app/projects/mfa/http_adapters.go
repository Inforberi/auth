package mfa

import (
	"context"

	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type ProjectBrowserMFAHTTP struct{ *ProjectMFA }

func (s ProjectBrowserMFAHTTP) Complete(ctx context.Context, input mfalogin.CompleteLoginInput) (*mfalogin.LoginSession, error) {
	return s.CompleteMFA(ctx, input)
}

func (s ProjectBrowserMFAHTTP) StartRequiredEnrollment(ctx context.Context, input mfalogin.LoginEnrollmentInput) (*mfaservice.Enrollment, error) {
	return s.StartMFAEnrollment(ctx, input)
}

func (s ProjectBrowserMFAHTTP) ConfirmRequiredEnrollment(ctx context.Context, input mfalogin.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error) {
	return s.ConfirmMFAEnrollment(ctx, input)
}

type ProjectRecoveryPrimary struct{ manager *ProjectMFA }

func (p ProjectRecoveryPrimary) Start(ctx context.Context, proof mfaservice.PrimaryProof, ip string) (*mfalogin.LoginChallenge, error) {
	var result *mfalogin.LoginChallenge
	err := p.manager.withMFA(ctx, func(ctx context.Context, login *mfalogin.Login) error {
		var err error
		result, err = login.Start(ctx, proof, ip)
		return err
	})
	return result, err
}
