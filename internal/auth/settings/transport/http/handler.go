package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type settingsService interface {
	Read(context.Context, accessservice.Principal) (domain.Snapshot, error)
	Update(context.Context, service.UpdateInput) (domain.Snapshot, error)
}

type Handler struct {
	service   settingsService
	available domain.PublicMethods
	log       *zap.Logger
	tokens    TokenProfilesResponse
}

func New(service settingsService, available domain.PublicMethods, log *zap.Logger) *Handler {
	return NewWithTokenDeployment(service, available, domain.TokenDeployment{}, log)
}

func NewWithTokenDeployment(service settingsService, available domain.PublicMethods, deployment domain.TokenDeployment, log *zap.Logger) *Handler {
	return &Handler{service: service, available: available, log: log, tokens: tokenProfilesResponse(deployment)}
}

func principal(w http.ResponseWriter, r *http.Request) (accessservice.Principal, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return accessservice.Principal{}, false
	}
	return accessservice.Principal{UserID: auth.UserID, TokenHash: auth.TokenHash}, true
}

type MethodsResponse struct {
	Password bool `json:"password"`
	EmailOTP bool `json:"emailOtp"`
	Google   bool `json:"google"`
	Telegram bool `json:"telegram"`
} // @name auth_settings_http.MethodsResponse

type RegistrationResponse struct {
	Enabled  bool `json:"enabled"`
	Google   bool `json:"google"`
	Telegram bool `json:"telegram"`
} // @name auth_settings_http.RegistrationResponse

type PolicyResponse struct {
	Methods                   MethodsResponse          `json:"methods"`
	Registration              RegistrationResponse     `json:"registration"`
	PasswordEmailVerification domain.EmailVerification `json:"passwordEmailVerification" swaggertype:"string" enums:"disabled,optional,required"`
	TokenIssuance             TokenIssuanceResponse    `json:"tokenIssuance"`
} // @name auth_settings_http.PolicyResponse

type TokenIssuanceResponse struct {
	SessionExchange bool `json:"sessionExchange"`
	Native          bool `json:"native"`
} // @name auth_settings_http.TokenIssuanceResponse

type SettingsResponse struct {
	Version          int64                 `json:"version"`
	Policy           PolicyResponse        `json:"policy"`
	AvailableMethods MethodsResponse       `json:"availableMethods"`
	TokenProfiles    TokenProfilesResponse `json:"tokenProfiles"`
} // @name auth_settings_http.SettingsResponse

func methodsResponse(methods domain.PublicMethods) MethodsResponse {
	return MethodsResponse{Password: methods.Password, EmailOTP: methods.EmailOTP, Google: methods.Google, Telegram: methods.Telegram}
}

func (h *Handler) respond(w http.ResponseWriter, snapshot domain.Snapshot) {
	policy := snapshot.Policy
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, SettingsResponse{
		Version: snapshot.Version,
		Policy: PolicyResponse{
			Methods:                   methodsResponse(policy.Methods),
			Registration:              RegistrationResponse{Enabled: policy.Registration.Enabled, Google: policy.Registration.Google, Telegram: policy.Registration.Telegram},
			PasswordEmailVerification: policy.PasswordEmailVerification,
			TokenIssuance:             TokenIssuanceResponse{SessionExchange: policy.TokenIssuance.SessionExchange, Native: policy.TokenIssuance.Native},
		},
		AvailableMethods: methodsResponse(h.available),
		TokenProfiles:    h.tokens,
	})
}
