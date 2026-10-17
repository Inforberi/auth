package mfahttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type management interface {
	StartEnrollment(context.Context, service.Proof) (*service.Enrollment, error)
	ConfirmEnrollment(context.Context, service.ConfirmInput) (*service.RecoveryCodes, error)
	StartReplacement(context.Context, service.Proof) (*service.Enrollment, error)
	ConfirmReplacement(context.Context, service.ConfirmInput) (*service.RecoveryCodes, error)
	StepUp(context.Context, service.StepUpInput) (*service.StepUpResult, error)
	Disable(context.Context, service.Proof) error
	RegenerateRecovery(context.Context, service.Proof) (*service.RecoveryCodes, error)
}

type login interface {
	Complete(context.Context, service.CompleteLoginInput) (*service.LoginSession, error)
	StartRequiredEnrollment(context.Context, service.LoginEnrollmentInput) (*service.Enrollment, error)
	ConfirmRequiredEnrollment(context.Context, service.ConfirmLoginEnrollmentInput) (*service.RecoveryCodes, error)
}

type recovery interface {
	Start(context.Context, service.StartRecoveryInput) (*service.RecoveryCandidate, error)
	Complete(context.Context, service.CompleteRecoveryInput) (*service.RecoveryCodes, error)
}

type Handler struct {
	management management
	login      login
	recovery   recovery
	log        *zap.Logger
}

func New(management management, login login, log *zap.Logger) *Handler {
	return NewWithRecovery(management, login, nil, log)
}

func NewWithRecovery(management management, login login, recovery recovery, log *zap.Logger) *Handler {
	return &Handler{management: management, login: login, recovery: recovery, log: log}
}

type StatusResponse struct {
	Status string `json:"status"`
} // @name mfa_http.StatusResponse

func requestProof(w http.ResponseWriter, r *http.Request) (service.Proof, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
		return service.Proof{}, false
	}
	return service.Proof{UserID: auth.UserID, TokenHash: auth.TokenHash, AuthVersion: auth.AuthVersion}, true
}
