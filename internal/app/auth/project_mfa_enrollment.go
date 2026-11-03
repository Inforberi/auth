package auth

import (
	"context"

	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (p *projectMFA) StartEnrollment(ctx context.Context, proof mfaservice.Proof) (*mfaservice.Enrollment, error) {
	var result *mfaservice.Enrollment
	err := p.withManagement(ctx, func(ctx context.Context, service *mfamanagement.Service) error {
		var err error
		result, err = service.StartEnrollment(ctx, proof)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *projectMFA) ConfirmEnrollment(ctx context.Context, input mfamanagement.ConfirmInput) (*mfaservice.RecoveryCodes, error) {
	var result *mfaservice.RecoveryCodes
	err := p.withManagement(ctx, func(ctx context.Context, service *mfamanagement.Service) error {
		var err error
		result, err = service.ConfirmEnrollment(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *projectMFA) StartReplacement(ctx context.Context, proof mfaservice.Proof) (*mfaservice.Enrollment, error) {
	var result *mfaservice.Enrollment
	err := p.withManagement(ctx, func(ctx context.Context, service *mfamanagement.Service) error {
		var err error
		result, err = service.StartReplacement(ctx, proof)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *projectMFA) ConfirmReplacement(ctx context.Context, input mfamanagement.ConfirmInput) (*mfaservice.RecoveryCodes, error) {
	var result *mfaservice.RecoveryCodes
	err := p.withManagement(ctx, func(ctx context.Context, service *mfamanagement.Service) error {
		var err error
		result, err = service.ConfirmReplacement(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
