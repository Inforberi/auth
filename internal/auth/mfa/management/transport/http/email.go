package mfamanagementhttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

type emailPreparation interface {
	Request(context.Context, mfaservice.Proof, string, string) (*otpservice.RequestedCode, error)
	Confirm(context.Context, otpservice.EmailPreparationConfirmation) (*otpservice.ReauthenticatedSession, error)
}

type emailFactors interface {
	Status(context.Context, mfaservice.Proof) (*domain.EmailFactor, error)
	Enable(context.Context, mfaservice.Proof) error
	Disable(context.Context, mfaservice.Proof) error
}

type EmailHandler struct {
	preparation emailPreparation
	factors     emailFactors
	log         *zap.Logger
}

func NewEmail(preparation emailPreparation, factors emailFactors, log *zap.Logger) (*EmailHandler, error) {
	if preparation == nil || factors == nil {
		return nil, domain.ErrUnavailable
	}
	return &EmailHandler{preparation: preparation, factors: factors, log: log}, nil
}

func (h *EmailHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	mfahttp.RespondEmailError(w, r, h.log, err)
}
