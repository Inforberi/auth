package mfaloginhttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

type login interface {
	Complete(context.Context, mfalogin.CompleteLoginInput) (*mfalogin.LoginSession, error)
	StartRequiredEnrollment(context.Context, mfalogin.LoginEnrollmentInput) (*mfaservice.Enrollment, error)
	ConfirmRequiredEnrollment(context.Context, mfalogin.ConfirmLoginEnrollmentInput) (*mfaservice.RecoveryCodes, error)
}

type Handler struct {
	login login
	log   *zap.Logger
}

func New(login login, log *zap.Logger) *Handler { return &Handler{login: login, log: log} }

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	mfahttp.RespondError(w, r, h.log, err)
}
