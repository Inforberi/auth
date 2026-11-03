package mfarecoveryhttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	mfarecovery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

type recovery interface {
	Start(context.Context, mfarecovery.StartRecoveryInput) (*mfarecovery.RecoveryCandidate, error)
	Complete(context.Context, mfarecovery.CompleteRecoveryInput) (*mfaservice.RecoveryCodes, error)
}

type Handler struct {
	recovery recovery
	log      *zap.Logger
}

func New(recovery recovery, log *zap.Logger) *Handler { return &Handler{recovery: recovery, log: log} }

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	mfahttp.RespondError(w, r, h.log, err)
}
