package mfamanagementhttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

type preferences interface {
	Read(context.Context, mfaservice.Proof) (domain.Preference, error)
	Update(context.Context, mfamanagement.PreferenceUpdate) (domain.Preference, error)
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
} // @name mfahttp.PreferenceResponse

func (h *PreferenceHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	mfahttp.RespondTelegramError(w, r, h.log, err)
}
