package http

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type providerSettings interface {
	Read(context.Context, accessservice.Principal, string) (domain.ProviderSnapshot, error)
	Update(context.Context, service.ProviderUpdateInput) (domain.ProviderSnapshot, error)
}

type ProviderHandler struct {
	service providerSettings
	log     *zap.Logger
}

func NewProviders(service providerSettings, log *zap.Logger) *ProviderHandler {
	return &ProviderHandler{service: service, log: log}
}

type ProviderResponse struct {
	Provider  string `json:"provider"`
	Version   int64  `json:"version"`
	ClientID  string `json:"clientId"`
	SecretSet bool   `json:"clientSecretSet"`
} // @name provider_settings_http.SettingsResponse

func (h *ProviderHandler) respond(w http.ResponseWriter, s domain.ProviderSnapshot) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, ProviderResponse{Provider: s.Provider, Version: s.Version, ClientID: s.ClientID, SecretSet: s.SecretSet})
}

var providerSettingsErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidProvider, 400, "invalid_provider_settings", "invalid provider settings"),
	httpx.MatchError(domain.ErrPolicyConflict, 409, "provider_settings_conflict", "provider settings changed; reload and retry"),
	httpx.MatchError(domain.ErrProviderClientBound, 409, "provider_client_bound", "client ID is bound to existing identities"),
}, settingsErrors...)

func (h *ProviderHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "provider_settings", err, providerSettingsErrors, httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}

func providerName(r *http.Request) string { return chi.URLParam(r, "provider") }
