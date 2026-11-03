package mfamanagementhttp

import (
	"context"

	"go.uber.org/zap"

	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type management interface {
	Status(context.Context, mfaservice.Proof) (*mfamanagement.SecurityStatus, error)
	StartEnrollment(context.Context, mfaservice.Proof) (*mfaservice.Enrollment, error)
	ConfirmEnrollment(context.Context, mfamanagement.ConfirmInput) (*mfaservice.RecoveryCodes, error)
	StartReplacement(context.Context, mfaservice.Proof) (*mfaservice.Enrollment, error)
	ConfirmReplacement(context.Context, mfamanagement.ConfirmInput) (*mfaservice.RecoveryCodes, error)
	StepUp(context.Context, mfamanagement.StepUpInput) (*mfamanagement.StepUpResult, error)
	Disable(context.Context, mfaservice.Proof) error
	RegenerateRecovery(context.Context, mfaservice.Proof) (*mfaservice.RecoveryCodes, error)
}

type Handler struct {
	management management
	log        *zap.Logger
}

func New(management management, log *zap.Logger) *Handler {
	return &Handler{management: management, log: log}
}
