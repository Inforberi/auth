package passwordrecoveryhttp

import (
	"context"

	"go.uber.org/zap"
)

type RecoveryService interface {
	Forgot(context.Context, string, string) error
	Reset(context.Context, string, string, string, string) error
}

type RecoveryHandler struct {
	service RecoveryService
	log     *zap.Logger
}

func NewRecovery(service RecoveryService, log *zap.Logger) *RecoveryHandler {
	return &RecoveryHandler{service: service, log: log}
}
