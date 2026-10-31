package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type emailMFASettings interface {
	Read(context.Context, accessservice.Principal) (domain.EmailMFASnapshot, error)
	Update(context.Context, service.EmailMFAUpdate) (domain.EmailMFASnapshot, error)
}

type EmailMFAHandler struct {
	service emailMFASettings
	log     *zap.Logger
}

func NewEmailMFA(service emailMFASettings, log *zap.Logger) *EmailMFAHandler {
	return &EmailMFAHandler{service: service, log: log}
}

type EmailMFASettingsResponse struct {
	Version int64 `json:"version"`
	Allowed bool  `json:"allowed"`
} // @name mfa_settings_http.EmailSettingsResponse

var emailMFASettingsErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidMFAPolicy, 400, "invalid_mfa_policy", "positive expectedVersion required"),
	httpx.MatchError(domain.ErrPolicyConflict, 409, "mfa_policy_conflict", "MFA policy changed; reload and retry"),
	httpx.MatchError(domain.ErrMethodNotReady, 409, "mfa_not_ready", "email MFA capability unavailable"),
	httpx.MatchError(domain.ErrEmailFactorInUse, 409, "email_factor_in_use", "email MFA is configured for users"),
}, settingsErrors...)

func (h *EmailMFAHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "email_mfa_settings", err, emailMFASettingsErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}

func (h *EmailMFAHandler) respond(w http.ResponseWriter, result domain.EmailMFASnapshot) {
	httpx.JSON(w, 200, EmailMFASettingsResponse{Version: result.Version, Allowed: result.Allowed})
}
