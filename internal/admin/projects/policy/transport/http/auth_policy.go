package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	sessions "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type authPolicyService interface {
	ReadAuthPolicy(context.Context, operatordomain.Principal, domain.DirectoryTarget) (settingsdomain.Snapshot, error)
	UpdateAuthPolicy(context.Context, operatordomain.Principal, domain.AuthPolicyUpdate) (domain.AuthPolicyResult, error)
	ReadAuthPolicyOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.AuthPolicyOutcome, error)
}

type authPolicyReadinessService interface {
	authPolicyService
	ReadAuthPolicyView(context.Context, operatordomain.Principal, domain.DirectoryTarget) (domain.AuthPolicyView, error)
}

type AuthPolicyHandler struct {
	sessions            ProjectSessions
	linkLifetimes       ProjectLinkLifetimes
	credentialLifetimes ProjectCredentialLifetimes
	loginBudgets        ProjectLoginBudgets
	operationBudgets    ProjectOperationBudgets
	frontend            ProjectFrontends
	telegramBot         ProjectTelegramBot
	delivery            ProjectDelivery
	mfa                 ProjectMFA
	retention           ProjectRetention
	inspection          authPolicyReadinessService
	service             authPolicyService
	available           settingsdomain.PublicMethods
	log                 *zap.Logger
}

func NewAuthPolicy(service authPolicyService, available settingsdomain.PublicMethods, log *zap.Logger) *AuthPolicyHandler {
	return &AuthPolicyHandler{service: service, available: available, log: log}
}

func NewAuthPolicyWithReadiness(service authPolicyReadinessService, log *zap.Logger) *AuthPolicyHandler {
	return &AuthPolicyHandler{service: service, inspection: service, log: log}
}

func (h *AuthPolicyHandler) settings(snapshot settingsdomain.Snapshot, readiness *domain.AuthPolicyReadiness) settingshttp.SettingsResponse {
	if readiness == nil {
		return settingshttp.SettingsResponseFrom(snapshot, h.available)
	}
	response := settingshttp.SettingsResponseWithDeployment(snapshot, readiness.Runtime.Methods, readiness.Tokens)
	response.Readiness = &settingshttp.ReadinessResponse{PolicyVersion: readiness.PolicyVersion, ObservedAt: readiness.ObservedAt, Features: readiness.Features}
	return response
}

type ProjectAuthPolicyResponse struct {
	OperationID domain.ID                      `json:"operationId" swaggertype:"string"`
	Status      string                         `json:"status" enums:"committed,unknown"`
	Settings    *settingshttp.SettingsResponse `json:"settings,omitempty" swaggertype:"object"`
	Changed     *bool                          `json:"changed,omitempty"`
	Replayed    bool                           `json:"replayed"`
} // @name project_http.ProjectAuthPolicyResponse

func (h *AuthPolicyHandler) result(operation domain.ID, committed bool, result domain.AuthPolicyResult) ProjectAuthPolicyResponse {
	response := ProjectAuthPolicyResponse{OperationID: operation, Status: "unknown"}
	if committed {
		snapshot := h.settings(result.Snapshot, result.Readiness)
		response.Status, response.Settings, response.Changed, response.Replayed = "committed", &snapshot, &result.Changed, result.Replayed
	}
	return response
}

func policyOperationLocation(project, operation domain.ID) string {
	return "/api/v1/platform/projects/" + string(project) + "/auth/settings/operations/" + string(operation)
}

var authPolicyErrors = append(append([]httpx.ErrorRule{
	httpx.MatchError(sessions.ErrInvalidBrowserPolicy, 400, "invalid_session_policy", "invalid browser session policy"),
	httpx.MatchError(settingsdomain.ErrInvalidLinkLifetime, 400, "invalid_link_lifetimes", "invalid link lifetimes"),
	httpx.MatchError(settingsdomain.ErrInvalidCredentialLifetime, 400, "invalid_credential_lifetimes", "invalid credential lifetimes"),
	httpx.MatchError(settingsdomain.ErrInvalidLoginBudget, 400, "invalid_login_budgets", "invalid login budgets"),
	httpx.MatchError(settingsdomain.ErrInvalidOperationBudgets, 400, "invalid_operation_budgets", "invalid operation budgets"),
	httpx.MatchError(settingsdomain.ErrInvalidFrontend, 400, "invalid_frontend", "invalid frontend policy"),
	httpx.MatchError(settingsdomain.ErrInvalidMFAPolicy, 400, "invalid_mfa_policy", "invalid MFA policy"),
	httpx.MatchError(settingsdomain.ErrInvalidRetention, 400, "invalid_retention", "invalid retention policy"),
	httpx.MatchError(settingsdomain.ErrInvalidSMTP, 400, "invalid_smtp", "invalid SMTP settings"),
	httpx.MatchError(settingsdomain.ErrInvalidTelegramBot, 400, "invalid_telegram_bot", "invalid Telegram bot settings"),
	httpx.MatchError(settingsdomain.ErrTelegramBotVerification, 503, "telegram_bot_verification_failed", "Telegram webhook registration failed"),
	httpx.MatchError(settingsdomain.ErrTelegramFactorInUse, 409, "telegram_factor_in_use", "Telegram factor is in use"),
	httpx.MatchError(settingsdomain.ErrTelegramBotLimited, 429, "rate_limited", "rate limited"),
	httpx.MatchError(settingsdomain.ErrInvalidProvider, 400, "invalid_provider", "invalid provider settings"),
	httpx.MatchError(settingsdomain.ErrProviderClientBound, 409, "provider_client_bound", "client has linked identities"),
	httpx.MatchError(settingsdomain.ErrRetentionConfirmation, 409, "confirmation_required", "shorter retention requires confirmation"),
	httpx.MatchError(settingsdomain.ErrNotInitialized, 409, "auth_settings_not_initialized", "project authentication settings are not initialized"),
	httpx.MatchError(domain.ErrNotFound, 404, "auth_operation_not_found", "authentication settings operation not found"),
	httpx.MatchError(domain.ErrAdmissionExpired, 503, "temporarily_unavailable", "temporarily unavailable"),
}, settingshttp.SettingsErrorRules()...), cataloghttp.CatalogErrorRules()...)

func (h *AuthPolicyHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "platform_auth_settings", err, authPolicyErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
