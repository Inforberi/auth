package mfahttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type preferences interface {
	Read(context.Context, service.Proof) (domain.Preference, error)
	Update(context.Context, service.PreferenceUpdate) (domain.Preference, error)
}

type PreferenceHandler struct {
	service preferences
	log     *zap.Logger
}

func NewPreferences(service preferences, log *zap.Logger) *PreferenceHandler {
	return &PreferenceHandler{service: service, log: log}
}

type PreferenceResponse struct {
	Version int64         `json:"version"`
	Method  domain.Method `json:"method"`
}

func (h *PreferenceHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	respondMFAError(w, r, h.log, err, telegramErrors)
}
