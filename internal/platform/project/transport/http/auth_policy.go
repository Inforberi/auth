package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
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
	inspection authPolicyReadinessService
	service    authPolicyService
	available  settingsdomain.PublicMethods
	log        *zap.Logger
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
	httpx.MatchError(settingsdomain.ErrNotInitialized, 409, "auth_settings_not_initialized", "project authentication settings are not initialized"),
	httpx.MatchError(domain.ErrNotFound, 404, "auth_operation_not_found", "authentication settings operation not found"),
	httpx.MatchError(domain.ErrAdmissionExpired, 503, "temporarily_unavailable", "temporarily unavailable"),
}, settingshttp.SettingsErrorRules()...), catalogErrors...)

func (h *AuthPolicyHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "platform_auth_settings", err, authPolicyErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
